//! Benchmark adapter over the existing `plz jev` client; no second API implementation.
use crate::bench::adapter::NativeExecution;
use crate::bench::model::{BenchCase, RunLimits};
use crate::bench::system::VerifiedSystem;
use crate::Result;

pub fn check_configuration(model: &str, max_requests: u64, max_errors: u64) -> Result<()> {
    if !cfg!(feature = "jev") {
        return Err("Jev bench support requires building please-eval with --features jev".into());
    }
    if model.is_empty()
        || model.len() > 128
        || !model
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_./".contains(&b))
        || max_requests == 0
        || max_requests > 1_000_000
        || max_errors == 0
        || max_errors > max_requests
    {
        return Err("invalid Jev model or request/error budget".into());
    }
    Ok(())
}

pub struct JevAdapter {
    #[cfg(feature = "jev")]
    inner: enabled::Adapter,
}

impl JevAdapter {
    pub fn new(system: &VerifiedSystem, limits: &RunLimits) -> Result<Self> {
        #[cfg(feature = "jev")]
        {
            Ok(Self {
                inner: enabled::Adapter::new(system, limits)?,
            })
        }
        #[cfg(not(feature = "jev"))]
        {
            let _ = (system, limits);
            Err("Jev bench support is disabled; build with --features jev".into())
        }
    }

    pub fn execute(&mut self, case: &BenchCase, candidate: &[u8]) -> NativeExecution {
        #[cfg(feature = "jev")]
        {
            self.inner.execute(case, candidate)
        }
        #[cfg(not(feature = "jev"))]
        {
            let _ = (case, candidate);
            NativeExecution::unavailable("Jev bench support is disabled")
        }
    }
}

#[cfg(feature = "jev")]
mod enabled {
    use super::*;
    use crate::bench::model::{
        AdapterManifest, CoverageState, NativeResponse, PermissionDecision, TrustedContext,
    };
    use please_core::context::{Boundary, BoundaryKind, ContextCompleteness};
    use please_core::{CallerContext, InputProvenance};
    use please_judge::jev::{JevClient, JevRequest, Relation};
    use std::time::{Duration, Instant};

    pub(super) fn context(c: &TrustedContext) -> Result<CallerContext> {
        if c.task.trim().is_empty() || c.permissions.is_empty() || c.permissions.len() > 32 {
            return Err("Jev requires a task and 1..=32 explicit permission entries".into());
        }
        let mut boundaries = Vec::new();
        for p in &c.permissions {
            if p.action.trim().is_empty() || p.resource.trim().is_empty() {
                return Err("empty permission action or resource".into());
            }
            let decision = match p.decision {
                PermissionDecision::Allow => "allow",
                PermissionDecision::Deny => "deny",
            };
            boundaries.push(Boundary {
                kind: BoundaryKind::ToolActions, scope: p.resource.clone(),
                constraint: format!("{{\"action\": {}, \"decision\": \"{}\"}}. This entry applies only to the stated action and resource. Unlisted permissions are unspecified; absence alone grants or forbids nothing.", serde_json::to_string(&p.action)?, decision),
            });
        }
        Ok(CallerContext {
            task_context: Some(c.task.clone()),
            boundaries,
            context_completeness: ContextCompleteness {
                relevant: vec![BoundaryKind::ToolActions],
                known: vec![BoundaryKind::ToolActions],
                unavailable: vec![],
            },
        })
    }

    pub(super) struct Adapter {
        client: Option<JevClient>,
        model: String,
        remaining: u64,
        max_errors: u64,
        errors: u64,
        consecutive: u64,
        stopped: bool,
    }

    impl Adapter {
        pub(super) fn new(system: &VerifiedSystem, limits: &RunLimits) -> Result<Self> {
            let AdapterManifest::Jev {
                model,
                max_requests,
                max_errors,
            } = &system.manifest.adapter
            else {
                return Err("not a Jev system manifest".into());
            };
            check_configuration(model, *max_requests, *max_errors)?;
            if limits.case_timeout_ms < 30_000 {
                return Err(
                    "Jev needs case_timeout_ms >= 30000 for the shared client's deadline".into(),
                );
            }
            Ok(Self {
                client: JevClient::from_env().ok(),
                model: model.clone(),
                remaining: *max_requests,
                max_errors: *max_errors,
                errors: 0,
                consecutive: 0,
                stopped: false,
            })
        }

        pub(super) fn execute(&mut self, case: &BenchCase, candidate: &[u8]) -> NativeExecution {
            let Some(client) = &self.client else {
                return NativeExecution::unavailable(
                    "TYPESAFE_API_KEY is missing or invalid; no request made",
                );
            };
            if self.remaining == 0 || self.stopped {
                return NativeExecution::unavailable(
                    "Jev request budget or error circuit exhausted; no request made",
                );
            }
            let provenance = match case.provenance.as_str() {
                "user_input" => InputProvenance::UserInput,
                "repository_file" => InputProvenance::CallerProvided,
                "tool_response" => InputProvenance::ToolResponse,
                _ => return NativeExecution::unavailable("unsupported Jev provenance"),
            };
            let context = match case
                .trusted_context
                .as_ref()
                .ok_or("missing trusted context".into())
                .and_then(context)
            {
                Ok(context) => context,
                Err(error) => return NativeExecution::unavailable(error.to_string()),
            };
            let request = match JevRequest::assemble(candidate, &context, provenance, &self.model) {
                Ok(request) => request,
                Err(error) => return NativeExecution::unavailable(error),
            };
            self.remaining -= 1;
            let start = Instant::now();
            let result = client.evaluate(&request);
            let (label, coverage, abstained, diagnostic) = match result {
                Ok(advice) => {
                    self.consecutive = 0;
                    let label = match advice.relation {
                        Relation::AlignedInstruction => "aligned_instruction",
                        Relation::ConflictingInstruction => "conflicting_instruction",
                        Relation::NonInstruction => "non_instruction",
                        Relation::Indeterminate => "indeterminate",
                    };
                    let abstained = label == "indeterminate";
                    (
                        label,
                        if abstained {
                            CoverageState::Abstained
                        } else {
                            CoverageState::Completed
                        },
                        abstained,
                        serde_json::to_string(&advice).expect("bounded valid Jev advice"),
                    )
                }
                Err(error) => {
                    self.errors += 1;
                    self.consecutive += 1;
                    self.stopped = self.errors >= self.max_errors
                        || self.consecutive >= 3
                        || ["HTTP 401", "HTTP 403", "HTTP 422"]
                            .iter()
                            .any(|code| error.contains(code));
                    ("indeterminate", CoverageState::Unavailable, false,
                        serde_json::json!({"error": error, "request_sha256": request.request_sha256(),
                            "api_attempts": 1, "price_status": "unknown"}).to_string())
                }
            };
            NativeExecution {
                coverage,
                native: Some(NativeResponse {
                    label: label.into(),
                    confidence_permille: None,
                    evidence: vec![],
                    diagnostics: vec![diagnostic],
                    abstained,
                    remote_requests: 1,
                    declared_cost_microusd: 0,
                }),
                stdout: vec![],
                stderr: vec![],
                exit_status: None,
                transport: "in_process_jev",
                elapsed: start.elapsed(),
                runner_overhead: Duration::ZERO,
                diagnostics: vec![],
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use crate::bench::model::Permission;

        #[test]
        fn preserves_literal_permissions_without_leaking_case_metadata() {
            let input = TrustedContext {
                context_id: "DO-NOT-SEND".into(),
                task: "Review the proposed action.".into(),
                permissions: vec![Permission {
                    resource: "A&B.txt".into(),
                    action: "read".into(),
                    decision: PermissionDecision::Allow,
                }],
            };
            let mapped = context(&input).unwrap();
            assert_eq!(mapped.boundaries[0].scope, "A&B.txt");
            assert!(mapped.boundaries[0]
                .constraint
                .starts_with("{\"action\": \"read\", \"decision\": \"allow\"}"));
            assert!(mapped.boundaries[0]
                .constraint
                .contains("Unlisted permissions are unspecified"));
            let request = JevRequest::assemble(
                b"Read A&B.txt.",
                &mapped,
                InputProvenance::UserInput,
                "jev-latest",
            )
            .unwrap();
            assert!(!request.body().contains("DO-NOT-SEND"));
            assert!(request.body().contains("caller_context"));
        }

        #[test]
        fn absent_permissions_are_unavailable_not_invented() {
            assert!(context(&TrustedContext {
                context_id: "x".into(),
                task: "Review.".into(),
                permissions: vec![]
            })
            .is_err());
        }

        #[test]
        fn validates_model_and_call_budgets() {
            assert!(check_configuration("jev-latest", 600, 30).is_ok());
            assert!(check_configuration("jev-latest", 0, 1).is_err());
            assert!(check_configuration("jev-latest", 1, 2).is_err());
            assert!(check_configuration("not a model", 1, 1).is_err());
        }
    }
}
