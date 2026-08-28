//! `finalize::with_ml` — the merge that may add findings and may never remove one (006 T016, T017).
//!
//! The judgement tier's equivalent, `rejudge`, is tested for the opposite property: it can only narrow.
//! The asymmetry is deliberate and is argued in `plan.md` D4 — the judge reads attacker-influenced text
//! and so must not be able to amplify, whereas the ML tier's weights are operator-chosen and pinned by
//! digest, and content reaches the classifier as input rather than as instruction.
//!
//! Which makes *this* file the one that has to pin the other half of the contract. A tier that may raise a
//! score is a tier that must be shown never to lower one, and never to lose a structural finding on the way.
//!
//! # What is deliberately not tested here
//!
//! The corroboration table. There isn't one any more: `contracts/ml-tier.md` originally required a second
//! signal before a classifier label could become a finding, and the second signal it named was the
//! embedding outlier score — which T008 then measured as a document-level detector at 3.1% TPR against a
//! 25% criterion. Gating findings on a signal that measured at noise would have suppressed the tier's
//! entire reason to exist. The requirement was dropped rather than propped up with a threshold nobody
//! could defend. What replaces it as false-positive control is the classifier threshold and SC-602's
//! regression check, and neither is a core concern — see `crates/ml/src/observe.rs`.

use please_core::finalize::evidence::{Evidence, Observation};
use please_core::finalize::plan::Bounds;
use please_core::finalize::{finalize, with_ml, Attribution};
use please_core::ruleset::Bands;
use please_core::verdict::{
    IncompleteCause, MlMode, MlReport, MlSegmentResult, Outcome, RulesetId, Span, TargetRef, Verdict,
};
use please_core::DetectionClass;

fn ruleset() -> RulesetId {
    RulesetId {
        name: "test.fixture".to_string(),
        version: "0.0.0".to_string(),
        digest: "0000000000000000".to_string(),
    }
}

fn bounds() -> Bounds {
    Bounds {
        max_input_bytes: 1_048_576,
        max_decode_depth: 3,
        max_matches_per_rule: 16,
        max_reasons: 64,
        max_excerpt_bytes: 256,
    }
}

fn attribution() -> Attribution {
    Attribution {
        target: TargetRef::buffer("test", 0),
        ruleset: ruleset(),
        bands: Bands::default(),
    }
}

fn observation(rule_id: &str, start: usize, severity: u8, class: DetectionClass) -> Observation {
    Observation {
        rule_id: rule_id.to_string(),
        class,
        span: Span::new(start, start + 4),
        matched: "test".to_string(),
        severity,
        description: "test rule".to_string(),
        chain: Vec::new(),
        suppressed_by: None,
    }
}

/// A report with one segment, standing in for a real run's attribution.
fn report() -> MlReport {
    MlReport::new(
        "protectai-deberta-v3-small",
        "89b085cd330414d3e7d9dd787870f315957e1e9f",
        "3f786850e387550fdab836ed7e6dc881de23001b",
        700,
        vec![MlSegmentResult::new(
            Span::new(0, 4),
            MlMode::Classify,
            Some(940),
            None,
        )],
    )
}

fn structural(observations: Vec<Observation>) -> Verdict {
    let mut evidence = Evidence::new();
    for observation in observations {
        evidence.observe(observation);
    }
    finalize(evidence, bounds(), attribution())
}

fn merge(structural: Verdict, ml: Vec<Observation>) -> Verdict {
    with_ml(structural, ml, report(), bounds(), &Bands::default())
}

// ── The score moves one way ─────────────────────────────────────────────────────────────────────

#[test]
fn adding_nothing_changes_nothing() {
    // The identity case, and the one the contract states as its invariant with an empty observation list:
    // `with_ml(v, [], report).score() >= v.score()`. Equality is the honest reading of it.
    let before = structural(vec![observation("a", 0, 50, DetectionClass::Override)]);
    let score_before = before.score();
    let reasons_before: Vec<String> = before
        .reasons()
        .iter()
        .map(|r| r.rule_id().to_string())
        .collect();

    let after = merge(before, Vec::new());

    assert_eq!(after.score(), score_before);
    let reasons_after: Vec<String> = after
        .reasons()
        .iter()
        .map(|r| r.rule_id().to_string())
        .collect();
    assert_eq!(reasons_after, reasons_before);
}

#[test]
fn a_lower_severity_ml_finding_cannot_pull_the_score_down() {
    // The failure mode worth naming: `aggregate` takes the MAXIMUM severity, so a naive implementation
    // that averaged, or that recomputed from the ML observations alone, would report a *lower* score after
    // adding evidence. The tier would then be actively harmful — worse than not running.
    let before = structural(vec![observation("a", 0, 80, DetectionClass::Override)]);
    assert_eq!(before.score(), 80);

    let after = merge(
        before,
        vec![observation("ml.classifier", 100, 10, DetectionClass::Override)],
    );

    assert!(
        after.score() >= 80,
        "score fell to {} after adding evidence",
        after.score()
    );
}

#[test]
fn the_contract_example_holds() {
    // T017's stated acceptance: a structural verdict at 50, two ML observations added, merged score >= 50
    // and the structural reasons unchanged.
    let before = structural(vec![observation("a", 0, 50, DetectionClass::Override)]);
    assert_eq!(before.score(), 50);

    let after = merge(
        before,
        vec![
            observation("ml.classifier", 100, 40, DetectionClass::AgentDirected),
            observation("ml.classifier", 200, 30, DetectionClass::Solicitation),
        ],
    );

    assert!(after.score() >= 50);
    assert!(after
        .reasons()
        .iter()
        .any(|r| r.rule_id() == "a" && r.severity() == 50));
}

#[test]
fn distinct_ml_classes_earn_the_corroboration_bonus() {
    // Not a special case for the ML tier — it is `aggregate`'s ordinary breadth term, and the point of the
    // test is that ML findings reach it on the same footing as structural ones rather than through a
    // parallel scoring path.
    let before = structural(vec![observation("a", 0, 50, DetectionClass::Override)]);
    let after = merge(
        before,
        vec![observation(
            "ml.classifier",
            100,
            50,
            DetectionClass::AgentDirected,
        )],
    );
    assert_eq!(after.score(), 55, "one extra distinct class is +5");
}

// ── Structural findings survive ─────────────────────────────────────────────────────────────────

#[test]
fn every_structural_reason_survives_the_merge() {
    let before = structural(vec![
        observation("a", 0, 50, DetectionClass::Override),
        observation("b", 10, 30, DetectionClass::Boundary),
        observation("c", 20, 20, DetectionClass::Concealment),
    ]);
    let expected: Vec<String> = before
        .reasons()
        .iter()
        .map(|r| r.rule_id().to_string())
        .collect();

    let after = merge(
        before,
        vec![observation("ml.classifier", 5, 40, DetectionClass::Override)],
    );

    for rule_id in expected {
        assert!(
            after.reasons().iter().any(|r| r.rule_id() == rule_id),
            "structural reason `{rule_id}` was lost"
        );
    }
}

#[test]
fn merged_reasons_are_ordered_by_offset_not_by_arrival() {
    // The ML observation lands at offset 5, between two structural ones. If the merge appended without
    // re-ordering, output would depend on which tier ran — and SC-011's byte-identical guarantee would
    // hold only for scans that happened to skip the ML tier.
    let before = structural(vec![
        observation("a", 0, 50, DetectionClass::Override),
        observation("c", 20, 20, DetectionClass::Concealment),
    ]);
    let after = merge(
        before,
        vec![observation("ml.classifier", 5, 40, DetectionClass::Boundary)],
    );

    let offsets: Vec<usize> = after.reasons().iter().map(|r| r.span().start).collect();
    assert_eq!(offsets, vec![0, 5, 20]);
}

// ── The report is attribution, and its absence is a claim ───────────────────────────────────────

#[test]
fn the_report_rides_along_with_the_verdict() {
    let after = merge(
        structural(vec![observation("a", 0, 50, DetectionClass::Override)]),
        Vec::new(),
    );
    let report = after.ml().expect("a merged verdict carries its report");
    assert_eq!(report.model(), "protectai-deberta-v3-small");
    assert_eq!(report.threshold(), 700);
    assert_eq!(report.segments().len(), 1);
}

#[test]
fn a_purely_structural_verdict_has_no_report() {
    // `None` distinguishes "no ML tier ran" from "it ran and cleared everything". The second returns a
    // report with segments and no findings; conflating them would make `--no-ml` unverifiable from output.
    assert!(structural(vec![observation("a", 0, 50, DetectionClass::Override)])
        .ml()
        .is_none());
}

#[test]
fn a_clean_verdict_the_tier_cleared_still_carries_its_report() {
    let after = merge(structural(Vec::new()), Vec::new());
    assert_eq!(after.outcome(), Outcome::Clean);
    assert!(
        after.ml().is_some(),
        "a tier that ran and found nothing must still be attributable"
    );
}

// ── A truncated verdict is refused, not silently mis-scored ─────────────────────────────────────

#[test]
fn a_truncated_verdict_is_refused_and_keeps_its_score() {
    // Same argument as `rejudge`'s D9 refusal: `finalize` scored before truncating, so the severities past
    // `max_reasons` are gone and recomputing from the survivors would LOWER the score — here while
    // claiming to have added evidence.
    let tight = Bounds {
        max_reasons: 2,
        ..bounds()
    };
    let mut evidence = Evidence::new();
    for index in 0..5 {
        evidence.observe(observation(
            &format!("rule{index}"),
            index * 10,
            60,
            DetectionClass::Override,
        ));
    }
    let before = finalize(evidence, tight, attribution());
    assert!(before.reasons_truncated());
    let score_before = before.score();

    let after = with_ml(
        before,
        vec![observation("ml.classifier", 100, 90, DetectionClass::Override)],
        report(),
        tight,
        &Bands::default(),
    );

    assert_eq!(after.score(), score_before, "the score must not move");
    assert!(
        after.ml().is_none(),
        "a refused merge must not claim the tier acted"
    );
    assert!(
        after
            .incomplete()
            .iter()
            .any(|gap| gap.cause() == IncompleteCause::TierUnavailable),
        "the refusal must be visible in the verdict"
    );
    assert!(
        !after
            .reasons()
            .iter()
            .any(|r| r.rule_id() == "ml.classifier"),
        "no ML finding may be applied on the refusal path"
    );
}
