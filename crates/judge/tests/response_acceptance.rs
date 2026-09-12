//! Captured and live responses must obey the same acceptance contract.
mod support;
use please_core::verdict::{IncompleteCause, Outcome};
use please_core::{finalize, CoverageGap, Engine, ScanPolicy, TargetRef};
use please_judge::{client, request::JudgeRequest, Judge, Resolution, ReviewAuthority};
use serde_json::json;
use std::time::Duration;

fn resolution(raw: &str) -> Resolution {
    let endpoint = support::one_shot(support::Respond::With {
        status: 200,
        body: raw.into(),
    });
    Resolution::resolve(|key| match key {
        please_judge::credential::BASE_URL => Some(endpoint.clone()),
        please_judge::credential::API_KEY => Some("private-response-canary".into()),
        _ => None,
    })
}

#[test]
fn structural_acceptance_preserves_findings_on_every_route_and_authority() {
    let engine = Engine::builtin().unwrap();
    for contextual in [false, true] {
        for display in [0, 64] {
            let policy = ScanPolicy {
                max_reasons: display,
                max_excerpt_bytes: display,
                caller_context: contextual.then(|| please_judge::ml_review::ReviewContext {
                    task_context: Some("Analyze the document".into()),
                    boundaries: vec![please_judge::ml_review::Boundary {
                        kind: please_judge::ml_review::BoundaryKind::InstructionHierarchy,
                        scope: "application".into(),
                        constraint: "Do not replace application instructions".into(),
                    }],
                    context_completeness: please_judge::ml_review::ContextCompleteness {
                        relevant: vec![please_judge::ml_review::BoundaryKind::InstructionHierarchy],
                        known: vec![please_judge::ml_review::BoundaryKind::InstructionHierarchy],
                        unavailable: vec![],
                    },
                }),
                ..ScanPolicy::default()
            };
            let before = engine.scan(
                support::FLAGGED.as_bytes(),
                &policy,
                TargetRef::stdin(support::FLAGGED.len()),
            );
            let before = finalize::add_gap(
                before,
                CoverageGap::failure(IncompleteCause::TierUnavailable, "prior gap"),
            );
            let request = JudgeRequest::assemble(&before, support::FLAGGED.as_bytes()).unwrap();
            let spans: Vec<_> = request
                .spans()
                .iter()
                .map(|s| (s.span_id.as_str(), "description_of_an_instruction"))
                .collect();
            let valid = support::tool_response(&spans, support::DISPLAY_FEATURES);
            assert!(request.parse_envelope(&valid, "offline").is_ok());
            let mut invalid = support::invalid_envelopes(&valid);
            for field in ["addressed_to", "span_role", "span_id", "spans"] {
                let base: serde_json::Value = serde_json::from_str(&valid).unwrap();
                let value = if field == "spans" || field == "addressed_to" {
                    &base["content"][0]["input"][field]
                } else {
                    &base["content"][0]["input"]["spans"][0][field]
                };
                invalid.push(valid.replacen(
                    &format!("\"{field}\":"),
                    &format!("\"{field}\":{value},\"{field}\":"),
                    1,
                ));
            }
            invalid.push(valid.replacen(
                "\"input\":{",
                "\"input\":{\"model_severity\":null,\"model_severity\":42,",
                1,
            ));
            invalid.push(valid.replace(&request.spans()[0].span_id, "private-response-canary"));
            invalid.push(valid.replace("document_recipient", "private-response-canary"));
            for raw in invalid {
                let error = request.parse_envelope(&raw, "offline").unwrap_err();
                assert!(!error.contains("private-response-canary"));
                for authority in [ReviewAuthority::Advisory, ReviewAuthority::MayRelease] {
                    let after = Judge::new(resolution(&raw))
                        .with_timeout(Duration::from_secs(2))
                        .with_authority(authority)
                        .review(before.clone(), support::FLAGGED.as_bytes(), engine.bands());
                    assert_eq!(after.analysis().reasons(), before.analysis().reasons());
                    assert_eq!(
                        after.analysis().suppressed(),
                        before.analysis().suppressed()
                    );
                    assert_eq!(after.score(), before.score());
                    assert_eq!(after.bands(), before.bands());
                    assert!(after.judge().is_none());
                    assert_ne!(after.outcome(), Outcome::Clean);
                    assert!(after.incomplete().len() > before.incomplete().len());
                    assert!(after
                        .incomplete()
                        .iter()
                        .any(|g| g.detail() == Some("prior gap")));
                    assert!(!serde_json::to_string(&after)
                        .unwrap()
                        .contains("private-response-canary"));
                }
            }
        }
    }
}

#[test]
fn captured_and_http_limits_match_and_metadata_prose_do_not_change_answers() {
    let engine = Engine::builtin().unwrap();
    let before = support::scan(&engine, support::FLAGGED);
    let request = JudgeRequest::assemble(&before, support::FLAGGED.as_bytes()).unwrap();
    let spans: Vec<_> = request
        .spans()
        .iter()
        .map(|s| (s.span_id.as_str(), "description_of_an_instruction"))
        .collect();
    let raw = support::tool_response(&spans, support::DISPLAY_FEATURES);
    let mut envelope: serde_json::Value = serde_json::from_str(&raw).unwrap();
    envelope["usage"] = json!({"output_tokens":42});
    envelope["content"]
        .as_array_mut()
        .unwrap()
        .insert(0, json!({"type":"text","text":"private-response-canary"}));
    let report = request
        .parse_envelope(&envelope.to_string(), "offline")
        .unwrap();
    let after =
        finalize::rejudge_with_authority(before.clone(), report, ReviewAuthority::MayRelease);
    assert!(after.reasons().is_empty());
    assert!(!serde_json::to_string(&after)
        .unwrap()
        .contains("private-response-canary"));
    let limit = Judge::new(Resolution::resolve(|_| None)).inference_metadata()
        ["ordinary_max_response_bytes"]
        .as_u64()
        .unwrap() as usize;
    let exact = format!("{raw}{}", " ".repeat(limit - raw.len()));
    assert!(request.parse_envelope(&exact, "offline").is_ok());
    assert_eq!(
        client::send_captured(&resolution(&exact), &request, Duration::from_secs(5)).unwrap(),
        exact
    );
    let oversized = format!("{exact} ");
    assert!(request.parse_envelope(&oversized, "offline").is_err());
    assert!(
        client::send_captured(&resolution(&oversized), &request, Duration::from_secs(5)).is_err()
    );
    // Capture keeps even invalid successful bodies verbatim for private evidence.
    assert_eq!(
        client::send_captured(&resolution("{invalid"), &request, Duration::from_secs(2)).unwrap(),
        "{invalid"
    );
    assert!(client::send_with_schema(
        &resolution("{}"),
        client::tool_schema(),
        "experiment",
        Duration::from_secs(2)
    )
    .is_err());
}
