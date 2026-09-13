use std::collections::BTreeMap;
use std::time::Instant;

use please_core::{InputProvenance, ScanProfile, TargetRef};

use crate::bench::adapter::NativeExecution;
use crate::bench::identity::{canonical_digest, display_text};
use crate::bench::model::{
    AdapterManifest, CoverageState, NativeEvidence, NativeResponse, PleaseMode,
};
use crate::bench::system::VerifiedSystem;
use crate::product::{Mode, Runtime};
use crate::scan::RuleSelection;
use crate::Result;

pub struct PleaseAdapter {
    engine: please_core::Engine,
    runtime: Runtime,
    provenance_mapping: BTreeMap<String, String>,
}

impl PleaseAdapter {
    pub fn new(system: &VerifiedSystem) -> Result<Self> {
        let AdapterManifest::Please {
            mode,
            profile,
            threshold,
            provenance_mapping,
            disabled_rules,
            ..
        } = &system.manifest.adapter
        else {
            return Err("not a PLEASE system manifest".into());
        };
        let engine = RuleSelection {
            rules: system.resolved_rules.clone(),
            disable: disabled_rules.clone(),
        }
        .engine()?;
        let profile = match profile.as_str() {
            "enforcement" => ScanProfile::Enforcement,
            "reference_analysis" => ScanProfile::ReferenceAnalysis,
            _ => return Err("invalid PLEASE profile after manifest validation".into()),
        };
        let mode = match mode {
            PleaseMode::Product => Mode::Product,
            PleaseMode::Mechanism => Mode::Mechanism,
        };
        let runtime = Runtime::structural(mode, profile, crate::metrics::parse_floor(threshold)?)?;
        Ok(Self {
            engine,
            runtime,
            provenance_mapping: provenance_mapping.clone(),
        })
    }

    pub fn runtime_identity(&self) -> serde_json::Value {
        self.runtime
            .metadata(&self.engine, "bench verified rule selection")
    }

    pub fn execute(&self, case_id: &str, provenance: &str, candidate: &[u8]) -> NativeExecution {
        let started = Instant::now();
        let mapped = self
            .provenance_mapping
            .get(provenance)
            .map(String::as_str)
            .unwrap_or("unspecified");
        let provenance = match mapped {
            "caller_provided" => InputProvenance::CallerProvided,
            "user_input" => InputProvenance::UserInput,
            "tool_response" => InputProvenance::ToolResponse,
            _ => InputProvenance::Unspecified,
        };
        let session = self
            .runtime
            .session_with_provenance(&self.engine, provenance);
        let verdict = session.scan(candidate, TargetRef::buffer(case_id, candidate.len()));
        let incomplete: Vec<_> = verdict
            .incomplete()
            .iter()
            .map(|item| item.cause().as_str().to_string())
            .collect();
        let detected =
            please_scan::ScanDecision::from_verdict(&verdict, session.policy().threshold)
                == please_scan::ScanDecision::AtOrAboveThreshold;
        let label = if detected {
            "detected"
        } else if incomplete.is_empty() {
            "not_detected"
        } else {
            "indeterminate"
        };
        let native = NativeResponse {
            label: label.into(),
            confidence_permille: None,
            evidence: verdict
                .analysis()
                .reasons()
                .iter()
                .map(|reason| NativeEvidence {
                    kind: format!("{}:{}", reason.class().as_str(), reason.rule_id()),
                    start: reason.span().start as u64,
                    end: reason.span().end as u64,
                    detail: display_text(reason.rule_id()),
                })
                .collect(),
            diagnostics: incomplete.clone(),
            abstained: false,
            remote_requests: 0,
            declared_cost_microusd: 0,
        };
        let native_bytes = serde_json::to_vec(&native).unwrap_or_default();
        NativeExecution {
            coverage: if detected || incomplete.is_empty() {
                CoverageState::Completed
            } else {
                CoverageState::Unavailable
            },
            native: Some(native),
            stdout: native_bytes,
            stderr: Vec::new(),
            exit_status: None,
            transport: "in_process",
            elapsed: started.elapsed(),
            runner_overhead: std::time::Duration::ZERO,
            diagnostics: incomplete,
        }
    }
}

pub fn runtime_identity(system: &VerifiedSystem) -> Result<serde_json::Value> {
    let adapter = PleaseAdapter::new(system)?;
    let identity = adapter.runtime_identity();
    // Force serialization now so attribution failures happen before a run directory is created.
    let _ = canonical_digest("please-bench-please-runtime/v1", &identity)?;
    Ok(identity)
}
