//! Regression checks from the 2026-09-14 review. Labels include caller task context;
//! the structural engine receives bytes and provenance, not that authorization context.
use please_core::{Engine, InputProvenance, ScanPolicy, TargetRef};

#[test]
fn authorized_email_imperatives_do_not_become_high_risk() {
    let engine = Engine::builtin().unwrap();
    for line in include_str!("data/email_review_scenarios.jsonl")
        .lines()
        .chain(include_str!("data/email_reviewer_requests.jsonl").lines())
    {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        if row["label"] != "benign" {
            continue;
        }
        let text = row["text"].as_str().unwrap();
        // Origin alone neither grants nor removes authorization to send material.
        for provenance in [
            InputProvenance::Unspecified,
            InputProvenance::CallerProvided,
            InputProvenance::UserInput,
            InputProvenance::ToolResponse,
        ] {
            let policy = ScanPolicy {
                provenance,
                ..ScanPolicy::default()
            };
            let verdict = engine.scan(text.as_bytes(), &policy, TargetRef::stdin(text.len()));
            assert_eq!(verdict.score(), 0, "{}: {provenance:?}: {text}", row["id"]);
            assert!(verdict.incomplete().is_empty());
        }
    }
}

#[test]
fn explicit_instruction_override_still_has_high_risk_evidence() {
    let engine = Engine::builtin().unwrap();
    for line in include_str!("data/email_review_scenarios.jsonl").lines() {
        let row: serde_json::Value = serde_json::from_str(line).unwrap();
        if row["slice"] != "explicit_override_control" {
            continue;
        }
        let text = row["text"].as_str().unwrap();
        let policy = ScanPolicy {
            provenance: InputProvenance::ToolResponse,
            ..ScanPolicy::default()
        };
        let verdict = engine.scan(text.as_bytes(), &policy, TargetRef::stdin(text.len()));
        assert!(verdict.score() >= 70, "{}: {text}", row["id"]);
        assert!(verdict
            .analysis()
            .reasons()
            .iter()
            .any(|r| r.rule_id().starts_with("override.")));
        assert!(verdict.incomplete().is_empty());
    }
}
