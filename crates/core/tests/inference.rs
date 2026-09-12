use please_core::finalize::{
    self,
    ml_review::{MlReviewOutcome, MlReviewReport, MlReviewScope},
    review::ReviewAuthority,
};
use please_core::inference::{InferenceIdentity, MlWindowResult};
use please_core::verdict::{MlMode, MlReport, MlSegmentResult};
use please_core::{Engine, ScanPolicy, Span, TargetRef, Verdict};
use std::collections::BTreeMap;

fn scan(version: &str, raw_score: u16) -> Verdict {
    let input = b"Ordinary document.";
    let engine = Engine::builtin().unwrap();
    let policy = ScanPolicy::default();
    let span = Span::new(0, input.len());
    let report = MlReport::new(
        "test",
        "revision",
        "a".repeat(64),
        700,
        vec![MlSegmentResult::new(
            span,
            MlMode::Classify,
            Some(900),
            None,
        )],
    )
    .with_input(input)
    .with_impact(policy.ml_impact)
    .with_inference(
        InferenceIdentity::new(BTreeMap::from([("recipe".into(), version.into())])),
        vec![MlWindowResult {
            index: 0,
            token_start: 0,
            token_end: 3,
            span,
            model_tokens: 5,
            raw_score,
        }],
    );
    finalize::with_ml(
        engine.scan(input, &policy, TargetRef::stdin(input.len())),
        vec![please_core::Observation {
            rule_id: "ml.classifier".into(),
            class: please_core::DetectionClass::AgentDirected,
            span,
            matched: String::from_utf8_lossy(input).into(),
            severity: 75,
            description: "test".into(),
            chain: vec![],
            excerpt_truncated: false,
            suppressed_by: None,
        }],
        report,
        please_core::ScanPlan::resolve(&policy).bounds(),
        engine.bands(),
    )
}
#[test]
fn identity_or_window_changes_invalidate_pending_clearance() {
    let before = scan("v1", 900);
    let scope = MlReviewScope::capture(&before, b"Ordinary document.").unwrap();
    let review = MlReviewReport::new(
        scope,
        "controlled",
        &"b".repeat(64),
        vec![MlReviewOutcome::NoSupportedViolation],
        true,
    );
    let released = finalize::ml_review::apply_with_authority(
        before,
        review.clone(),
        ReviewAuthority::MayRelease,
    );
    assert!(released.reasons().is_empty());
    for changed in [scan("v2", 900), scan("v1", 800)] {
        let after = finalize::ml_review::apply_with_authority(
            changed.clone(),
            review.clone(),
            ReviewAuthority::MayRelease,
        );
        assert!(after.is_incomplete());
        assert_eq!(after.reasons(), changed.reasons());
        assert!(after.ml_review().is_none());
    }
}
#[test]
fn presentation_does_not_erase_window_evidence() {
    let before = scan("v1", 900);
    let after = before
        .clone()
        .into_analysis()
        .report(please_core::DisplayLimits {
            max_reasons: 0,
            max_excerpt_bytes: 0,
        });
    assert_eq!(before.ml(), after.ml());
    assert_eq!(before.score(), after.score());
    assert!(MlReviewScope::capture(&after, b"Ordinary document.").is_ok());
}
