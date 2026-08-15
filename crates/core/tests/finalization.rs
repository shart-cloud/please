//! The invariant everything else rests on: a clean verdict means the whole input was examined.
//!
//! If these tests pass and nothing else does, the tool is still honest — it will say "I could not tell"
//! instead of "this is fine". If these fail and everything else passes, the tool is worse than absent,
//! because it reports safety it never established.
//!
//! # This file was `invariants.rs` (T024)
//!
//! Every test moved, and every one changed shape. They used to construct a `Verdict` directly, through the
//! public `Verdict::assemble(VerdictParts { .. })`, which was the only way to reach the invariant without
//! an engine — and also the reason the invariant needed testing this hard, because any caller could do the
//! same thing in production.
//!
//! They now construct **evidence** and call finalization, which is the only producer (FR-120). Two things
//! improve:
//!
//!  * the test exercises the real path. `Verdict::assemble` was a function only tests and `engine.rs`
//!    called; `finalize` is what every scan goes through, so a test here covers the production route
//!    rather than a parallel one;
//!  * the thing the old tests were defending against is now impossible. A caller cannot hand finalization
//!    a set of reasons and a `Clean` outcome, because a caller cannot build a `Reason` at all. See
//!    `tests/compile_fail/` for the assertion that this is so.
//!
//! What is still worth testing here is that *finalization itself* derives the outcome correctly from
//! arbitrary evidence — including combinations a real scan cannot easily produce, which is the point of
//! being able to build evidence by hand.
//!
//! The record of the move is in `docs/002-test-inventory-before.txt` (SC-112).

use please_core::finalize::evidence::{CoverageGap, Evidence, Observation};
use please_core::finalize::plan::Bounds;
use please_core::finalize::{finalize, Attribution};
use please_core::verdict::{
    IncompleteCause, Outcome, RiskLevel, RulesetId, Span, TargetRef, Verdict,
};
use please_core::DetectionClass;

fn ruleset() -> RulesetId {
    RulesetId {
        name: "test.fixture".to_string(),
        version: "0.0.0".to_string(),
        digest: "0000000000000000".to_string(),
    }
}

/// Default bounds, generous enough that nothing truncates unless a test asks it to.
fn bounds() -> Bounds {
    Bounds {
        max_input_bytes: 1_048_576,
        max_decode_depth: 3,
        max_matches_per_rule: 16,
        max_reasons: 64,
        max_excerpt_bytes: 256,
    }
}

fn attribution(score: u8, risk: RiskLevel) -> Attribution {
    Attribution {
        score,
        risk,
        target: TargetRef::buffer("test", 0),
        ruleset: ruleset(),
    }
}

fn an_observation(rule_id: &str, start: usize, severity: u8) -> Observation {
    Observation {
        rule_id: rule_id.to_string(),
        class: DetectionClass::Override,
        span: Span::new(start, start + 4),
        matched: "test".to_string(),
        severity,
        description: "test rule".to_string(),
        chain: Vec::new(),
    }
}

/// Finalize the given evidence at default bounds and a score of zero.
fn verdict_from(evidence: Evidence) -> Verdict {
    finalize(evidence, bounds(), attribution(0, RiskLevel::None))
}

// ── Clean requires BOTH accumulators empty ─────────────────────────────────────────────────────

#[test]
fn clean_when_nothing_found_and_nothing_unexamined() {
    let v = verdict_from(Evidence::new());
    assert_eq!(v.outcome(), Outcome::Clean);
    assert_eq!(v.score(), 0);
}

#[test]
fn not_clean_when_a_bound_was_hit_even_with_no_observations() {
    // The whole fail-closed posture in one assertion. An oversized input found nothing *because it was
    // never looked at*, and reporting that as clean is the failure this project exists to avoid.
    let mut evidence = Evidence::new();
    evidence.record_gap(CoverageGap::bound(
        IncompleteCause::InputSize,
        1_048_576,
        "input is 2 MiB",
    ));
    assert_eq!(
        verdict_from(evidence).outcome(),
        Outcome::Inconclusive,
        "a scan that hit a bound must never be clean"
    );
}

#[test]
fn not_clean_when_a_target_was_unreadable() {
    let mut evidence = Evidence::new();
    evidence.record_gap(CoverageGap::failure(
        IncompleteCause::TargetUnreadable,
        "permission denied",
    ));
    assert_eq!(verdict_from(evidence).outcome(), Outcome::Inconclusive);
}

#[test]
fn not_clean_when_an_optional_tier_was_unavailable() {
    // Principle I: an unavailable tier degrades to inconclusive, never to clean. A caller may choose to
    // treat that as passing; the engine must not choose for them.
    let mut evidence = Evidence::new();
    evidence.record_gap(CoverageGap::failure(
        IncompleteCause::TierUnavailable,
        "classifier tier not built",
    ));
    assert_eq!(verdict_from(evidence).outcome(), Outcome::Inconclusive);
}

#[test]
fn risk_found_when_a_rule_fired() {
    let mut evidence = Evidence::new();
    evidence.observe(an_observation("override.ignore_previous", 10, 85));
    let v = finalize(evidence, bounds(), attribution(85, RiskLevel::High));
    assert_eq!(v.outcome(), Outcome::RiskFound);
}

#[test]
fn clean_verdict_carries_zero_score() {
    // A clean verdict with a non-zero score would be incoherent: the score exists to summarise findings,
    // and there are none. Finalization discards the score rather than trusting it, so a scoring bug shows
    // up as a failing test instead of as a confusing "clean, score 42" verdict.
    let v = finalize(Evidence::new(), bounds(), attribution(42, RiskLevel::Low));
    assert_eq!(v.outcome(), Outcome::Clean);
    assert_eq!(v.score(), 0, "a clean verdict must report score 0");
    assert_eq!(v.risk(), RiskLevel::None);
}

// ── Precedence ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn risk_found_outranks_inconclusive() {
    // Found a real payload AND ran out of budget. Reporting inconclusive would discard a confirmed
    // detection; the verdict is risk_found and carries the gap so the caller knows there may be more.
    let mut evidence = Evidence::new();
    evidence.observe(an_observation("override.ignore_previous", 10, 85));
    evidence.record_gap(CoverageGap::bound(
        IncompleteCause::MaxMatchesPerRule,
        16,
        "rule `override.ignore_previous` saturated",
    ));

    let v = finalize(evidence, bounds(), attribution(85, RiskLevel::High));
    assert_eq!(v.outcome(), Outcome::RiskFound);
    assert!(v.is_incomplete(), "the coverage gap must still be visible");
}

#[test]
fn outcome_rank_orders_risk_above_inconclusive_above_clean() {
    assert!(Outcome::RiskFound.rank() > Outcome::Inconclusive.rank());
    assert!(Outcome::Inconclusive.rank() > Outcome::Clean.rank());
}

// ── Ordering and truncation ────────────────────────────────────────────────────────────────────

#[test]
fn reasons_are_ordered_by_offset_then_rule_id() {
    // Deterministic output is a requirement rather than a nicety (FR-030, SC-011): it is what lets a
    // caller cache a verdict and diff it in CI. Recorded out of order on purpose.
    let mut evidence = Evidence::new();
    evidence.observe(an_observation("z.late", 40, 50));
    evidence.observe(an_observation("b.same_offset", 10, 50));
    evidence.observe(an_observation("a.same_offset", 10, 50));

    let v = verdict_from(evidence);
    let ids: Vec<&str> = v.reasons().iter().map(|r| r.rule_id()).collect();
    assert_eq!(ids, ["a.same_offset", "b.same_offset", "z.late"]);
}

#[test]
fn truncation_keeps_the_earliest_reasons_and_records_the_bound() {
    // Truncating after ordering, not before: the reasons kept must be the earliest in the input rather
    // than whichever the detector iteration order happened to produce.
    let mut evidence = Evidence::new();
    for i in (0..10).rev() {
        evidence.observe(an_observation(&format!("r.{i}"), i * 8, 50));
    }

    let limited = Bounds {
        max_reasons: 3,
        ..bounds()
    };
    let v = finalize(evidence, limited, attribution(50, RiskLevel::Medium));

    assert!(v.reasons_truncated());
    let ids: Vec<&str> = v.reasons().iter().map(|r| r.rule_id()).collect();
    assert_eq!(ids, ["r.0", "r.1", "r.2"]);
    assert!(
        v.incomplete()
            .iter()
            .any(|i| i.cause() == IncompleteCause::MaxReasons),
        "a truncated report is incomplete coverage and must say so"
    );
}

// ── The observation-to-reason transition (T017, moved from detect/mod.rs) ──────────────────────

#[test]
fn an_excerpt_is_neutralised_on_the_way_into_a_reason() {
    // Was `detect::tests::a_reason_built_from_a_hit_is_sanitised`, which tested `Hit::into_reason`. That
    // method no longer exists: a detector cannot build a reason, so neutralisation happens at the one
    // boundary that does (FR-021, FR-126).
    let mut observation = an_observation("override.x", 0, 80);
    observation.matched = "ignore\u{1b}[2J\u{202e}".to_string();

    let mut evidence = Evidence::new();
    evidence.observe(observation);

    let v = finalize(evidence, bounds(), attribution(80, RiskLevel::High));
    let matched = v.reasons()[0].matched();
    assert!(!matched.contains('\u{1b}'), "escape survived: {matched:?}");
    assert!(!matched.contains('\u{202e}'), "bidi survived: {matched:?}");
}

#[test]
fn a_truncated_excerpt_is_recorded_as_a_coverage_gap() {
    // The fourth of 001's four gap booleans (FR-122). Sanitisation returns "I shortened this", and the
    // only place that knows whose excerpt it was and what the bound was called is here.
    let mut observation = an_observation("override.x", 0, 80);
    observation.matched = "a".repeat(500);

    let mut evidence = Evidence::new();
    evidence.observe(observation);

    let tight = Bounds {
        max_excerpt_bytes: 16,
        ..bounds()
    };
    let v = finalize(evidence, tight, attribution(80, RiskLevel::High));

    let gap = v
        .incomplete()
        .iter()
        .find(|i| i.cause() == IncompleteCause::ExcerptLength)
        .expect("a shortened excerpt is a gap in what the reader can see");
    assert_eq!(gap.configured(), Some(16));
    assert!(
        gap.detail().is_some_and(|d| d.contains("override.x")),
        "the gap must name whose excerpt was shortened, got {:?}",
        gap.detail()
    );
}

// ── The invariant holds for arbitrary evidence ─────────────────────────────────────────────────

proptest::proptest! {
    /// For any combination of observations and coverage gaps, `Clean` implies both are empty.
    ///
    /// Stated as an implication rather than a case analysis so that it keeps holding when a tenth
    /// `IncompleteCause` or an eighth field arrives.
    #[test]
    fn clean_implies_nothing_found_and_nothing_missed(
        observation_count in 0usize..6,
        gap_count in 0usize..6,
        score in 0u8..=100,
    ) {
        let mut evidence = Evidence::new();
        for i in 0..observation_count {
            evidence.observe(an_observation(&format!("test.rule_{i}"), i * 8, 50));
        }
        for i in 0..gap_count {
            evidence.record_gap(CoverageGap::bound(
                IncompleteCause::MaxMatchesPerRule,
                i as u64,
                format!("rule `test.rule_{i}` saturated"),
            ));
        }

        let v = finalize(evidence, bounds(), attribution(score, RiskLevel::Medium));

        if v.outcome() == Outcome::Clean {
            proptest::prop_assert!(
                v.reasons().is_empty() && v.incomplete().is_empty(),
                "clean verdict had {} reasons and {} gaps",
                v.reasons().len(),
                v.incomplete().len(),
            );
            proptest::prop_assert_eq!(v.score(), 0);
        }

        // The contrapositive, which is the direction that actually protects a caller.
        if !v.incomplete().is_empty() {
            proptest::prop_assert_ne!(
                v.outcome(),
                Outcome::Clean,
                "recorded a coverage gap but reported clean",
            );
        }
    }
}

// ── The short-circuit producers ────────────────────────────────────────────────────────────────

#[test]
fn an_oversized_input_is_inconclusive_and_names_the_limit() {
    // T018's construction site. In 001 this branch built its own verdict and had to get `score: 0` and
    // `risk: None` right independently of the other two producers.
    let v = please_core::finalize::oversized(1024, 4096, TargetRef::buffer("big", 4096), ruleset());
    assert_eq!(v.outcome(), Outcome::Inconclusive);
    assert_eq!(v.score(), 0);
    let gap = &v.incomplete()[0];
    assert_eq!(gap.cause(), IncompleteCause::InputSize);
    assert_eq!(gap.configured(), Some(1024));
    assert!(gap.detail().is_some_and(|d| d.contains("4096")));
}

#[test]
fn an_unreadable_target_is_inconclusive_and_never_skipped() {
    // T020's construction site (FR-032a). The failure mode this closes is one level up: a directory
    // reported clean on the strength of files nobody read.
    let v = please_core::finalize::unreadable_target(
        TargetRef::path("secret.txt", 0),
        "permission denied",
        ruleset(),
    );
    assert_eq!(v.outcome(), Outcome::Inconclusive);
    let gap = &v.incomplete()[0];
    assert_eq!(gap.cause(), IncompleteCause::TargetUnreadable);
    assert_eq!(gap.configured(), None, "a failure has no limit to raise");
    assert_eq!(gap.detail(), Some("permission denied"));
}
