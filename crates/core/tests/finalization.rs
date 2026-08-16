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
use please_core::ruleset::Bands;
use please_core::verdict::{
    IncompleteCause, Outcome, QuotingContext, RiskLevel, RulesetId, Span, SuppressedBy, TargetRef,
    Verdict,
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

/// Where the verdict came from, and the band table it scores against.
///
/// Since T060 this carries no score and no risk: finalization derives both from the evidence it was handed.
/// Before that, a caller passed them in — which meant the caller was holding its own view of the
/// observations in order to compute them, which is the shape FR-124 removes.
fn attribution() -> Attribution {
    Attribution {
        target: TargetRef::buffer("test", 0),
        ruleset: ruleset(),
        bands: Bands::default(),
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
        suppressed_by: None,
    }
}

/// Finalize the given evidence at default bounds and a score of zero.
fn verdict_from(evidence: Evidence) -> Verdict {
    finalize(evidence, bounds(), attribution())
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
    let v = finalize(evidence, bounds(), attribution());
    assert_eq!(v.outcome(), Outcome::RiskFound);
}

#[test]
fn clean_verdict_carries_zero_score() {
    // A clean verdict with a non-zero score would be incoherent: the score exists to summarise findings,
    // and there are none.
    //
    // 001 achieved this by accepting a caller's score and then discarding it, which is the "silent
    // adjustment" FR-127 objects to: the call site read `score: 42` and the verdict said 0. Now there is no
    // score to discard — an empty accumulator aggregates to 0 because that is what aggregating nothing
    // gives, and the coherence is arithmetic rather than a correction.
    let v = finalize(Evidence::new(), bounds(), attribution());
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

    let v = finalize(evidence, bounds(), attribution());
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
    let v = finalize(evidence, limited, attribution());

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

    let v = finalize(evidence, bounds(), attribution());
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
    let v = finalize(evidence, tight, attribution());

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

// ── FR-124, SC-109: the score aggregates over everything, then reasons truncate ────────────────

#[test]
fn the_score_reflects_every_observation_when_the_report_is_truncated_to_one() {
    // SC-109, and the reason the two-collections shape existed. Reasons are ordered by BYTE OFFSET, not by
    // severity, so truncating first can drop the worst finding — and a score computed after truncation would
    // then understate the risk of the very input it was summarising.
    //
    // The severe finding is placed LAST in the input on purpose. Under `max_reasons: 1` only the earliest
    // survives into the report, so if the score were derived from what is reported it would read 20.
    let mut evidence = Evidence::new();
    evidence.observe(an_observation("a.mild", 0, 20));
    evidence.observe(an_observation("b.moderate", 100, 55));
    evidence.observe(an_observation("c.severe", 200, 95));

    let one = Bounds {
        max_reasons: 1,
        ..bounds()
    };
    let v = finalize(evidence, one, attribution());

    assert_eq!(v.reasons().len(), 1, "the report is truncated");
    assert_eq!(
        v.reasons()[0].rule_id(),
        "a.mild",
        "the earliest by offset is what survives truncation"
    );
    assert_eq!(
        v.score(),
        95,
        "the score must summarise every observation, not the one that fitted"
    );
    assert!(
        v.reasons_truncated(),
        "and the reader must be told the report is partial"
    );
}

#[test]
fn a_score_cannot_be_supplied_by_a_caller_at_all() {
    // FR-127. This is not "the caller's score is validated" or "corrected" — there is nowhere to put one.
    // 001 accepted `score` and `risk` in `VerdictParts` and then overwrote them for non-`RiskFound`
    // outcomes, which is a silent adjustment invisible at the call site: the code read `score: 42` and the
    // verdict said 0.
    //
    // Asserted by construction: `Attribution` has three fields and none of them is a score. If that ever
    // changes, this test stops compiling, which is the notification we want.
    let attribution = Attribution {
        target: TargetRef::buffer("test", 0),
        ruleset: ruleset(),
        bands: Bands::default(),
    };
    let mut evidence = Evidence::new();
    evidence.observe(an_observation("a.one", 0, 70));
    let v = finalize(evidence, bounds(), attribution);
    assert_eq!(
        v.score(),
        70,
        "derived from the evidence and from nothing else"
    );
}

#[test]
fn risk_is_the_band_the_score_falls_into_under_the_supplied_table() {
    // The band table is data a deployment can retune, so it is an input; the score is not. Distinguishing
    // those two is what FR-127 asks for — the derivation belongs to finalization, the calibration does not.
    let mut evidence = Evidence::new();
    evidence.observe(an_observation("a.one", 0, 50));

    let strict = Attribution {
        bands: Bands {
            low: 10,
            medium: 20,
            high: 30,
            critical: 40,
        },
        ..attribution()
    };
    let v = finalize(evidence, bounds(), strict);
    assert_eq!(v.score(), 50);
    assert_eq!(
        v.risk(),
        RiskLevel::Critical,
        "50 is above a critical boundary of 40"
    );
}

// ── T055: combinations a real scan cannot easily produce ───────────────────────────────────────

#[test]
fn a_saturated_rule_and_a_truncated_excerpt_and_a_found_payload_at_once() {
    // The point of being able to build evidence by hand. Arranging all three of these in one real scan means
    // finding an input that matches one rule more than sixteen times, carries an excerpt over the byte cap,
    // AND trips a second rule — reachable, but the test would then be about the input rather than about
    // finalization, and it would break whenever the rules changed.
    //
    // What must hold when they coincide: the verdict is `RiskFound` (a confirmed payload outranks any gap),
    // the score reflects the worst observation, and **all three** gaps are reported. A verdict that reported
    // the payload and dropped the gaps would be claiming coverage it did not have.
    let mut evidence = Evidence::new();

    let mut long_excerpt = an_observation("a.verbose", 0, 40);
    long_excerpt.matched = "x".repeat(500);
    evidence.observe(long_excerpt);

    evidence.observe(an_observation("b.payload", 50, 90));

    evidence.record_gap(CoverageGap::bound(
        IncompleteCause::MaxMatchesPerRule,
        16,
        "rule `c.repetitive` saturated",
    ));

    let tight = Bounds {
        max_excerpt_bytes: 32,
        ..bounds()
    };
    let v = finalize(evidence, tight, attribution());

    assert_eq!(
        v.outcome(),
        Outcome::RiskFound,
        "a confirmed payload outranks every coverage gap"
    );
    assert_eq!(v.score(), 90, "the worst observation sets the score");

    let causes: Vec<IncompleteCause> = v.incomplete().iter().map(|i| i.cause()).collect();
    assert!(
        causes.contains(&IncompleteCause::MaxMatchesPerRule),
        "the saturated rule must still be reported: {causes:?}"
    );
    assert!(
        causes.contains(&IncompleteCause::ExcerptLength),
        "the truncated excerpt must still be reported: {causes:?}"
    );
    assert_eq!(
        v.reasons().len(),
        2,
        "both findings are reported; neither gap suppressed a finding"
    );
}

#[test]
fn a_gap_recorded_after_the_last_observation_is_still_reported() {
    // Ordering inside the accumulator must not affect what a verdict says. A gap recorded before any
    // observation and one recorded after must both survive — the accumulator is append-only and
    // finalization reads all of it, so this is really a test that nothing takes a shortcut on the empty
    // case.
    let mut evidence = Evidence::new();
    evidence.record_gap(CoverageGap::failure(
        IncompleteCause::DecodeFailed,
        "recorded first, before anything was found",
    ));
    evidence.observe(an_observation("a.one", 0, 60));
    evidence.record_gap(CoverageGap::bound(
        IncompleteCause::DecodeDepth,
        3,
        "recorded last, after the finding",
    ));

    let v = verdict_from(evidence);
    assert_eq!(v.outcome(), Outcome::RiskFound);
    assert_eq!(
        v.incomplete().len(),
        2,
        "both gaps must be reported regardless of when they were recorded"
    );
}

// ── FR-128: suppression is evidence, not a discard ─────────────────────────────────────────────

#[test]
fn a_suppressed_observation_is_retained_with_the_context_that_suppressed_it() {
    // Acceptance scenario 1. 001 computed the suppressed list and dropped it on the floor with
    // `let _ = suppressed;`, so the principal lever on the false-positive problem had no observable effect
    // in a single run.
    let mut evidence = Evidence::new();
    evidence.suppress(
        an_observation("override.disregard_prior", 20, 85),
        QuotingContext::QuotedString,
    );

    let v = verdict_from(evidence);
    assert_eq!(
        v.suppressed().len(),
        1,
        "the suppressed observation must be retained"
    );
    let hidden = &v.suppressed()[0];
    assert_eq!(hidden.rule_id(), "override.disregard_prior");
    assert_eq!(
        hidden.suppressed_by(),
        Some(SuppressedBy::Quoting(QuotingContext::QuotedString)),
        "and it must say WHICH context hid it — 'something was suppressed' is not actionable"
    );
}

#[test]
fn a_suppressed_observation_is_not_a_finding() {
    // The invariant that makes retention safe. A suppressed observation must not reach the score, must not
    // make the outcome `RiskFound`, and must not appear among the reported reasons — otherwise "retained as
    // evidence" would silently mean "reported after all", and every security-prose document would go back
    // to being a false positive.
    let mut evidence = Evidence::new();
    evidence.suppress(
        an_observation("override.disregard_prior", 20, 95),
        QuotingContext::FencedCode,
    );

    let v = verdict_from(evidence);
    assert_eq!(
        v.outcome(),
        Outcome::Clean,
        "nothing was reported and nothing went unexamined, so the verdict is clean"
    );
    assert_eq!(v.score(), 0, "a suppressed observation must not score");
    assert!(v.reasons().is_empty());
    assert_eq!(v.suppressed().len(), 1, "but it is still on the record");
}

#[test]
fn suppression_is_not_a_coverage_gap() {
    // Deliberate, and worth stating because the opposite is tempting. Suppressed content WAS examined; a
    // policy chose not to report it. Recording it as incompleteness would turn every document that quotes a
    // payload — which is every threat model and advisory — into `Inconclusive`, and that is the exact
    // population suppression exists to serve.
    let mut evidence = Evidence::new();
    evidence.suppress(
        an_observation("override.disregard_prior", 0, 85),
        QuotingContext::BlockQuote,
    );
    let v = verdict_from(evidence);
    assert!(
        v.incomplete().is_empty(),
        "suppression is a reporting decision, not a gap in coverage: {:?}",
        v.incomplete()
    );
}

#[test]
fn a_suppressed_excerpt_is_neutralised_like_any_other() {
    // `--explain` prints these, so FR-021 applies to them exactly as it does to reported reasons. A payload
    // that could forge output from the suppressed list would be a payload that benefits from being quoted.
    let mut observation = an_observation("override.x", 0, 80);
    observation.matched = "ignore\u{1b}[2J\u{202e}".to_string();

    let mut evidence = Evidence::new();
    evidence.suppress(observation, QuotingContext::InlineCode);

    let v = verdict_from(evidence);
    let matched = v.suppressed()[0].matched();
    assert!(!matched.contains('\u{1b}'), "escape survived: {matched:?}");
    assert!(!matched.contains('\u{202e}'), "bidi survived: {matched:?}");
}

#[test]
fn suppressions_are_ordered_and_bounded_like_reasons() {
    // Bounded for the same reason reasons are (FR-007): a document quoting ten thousand payloads must not
    // produce a ten-thousand-entry report. Ordered for the same reason too — byte-identical output.
    let mut evidence = Evidence::new();
    for i in (0..10).rev() {
        evidence.suppress(
            an_observation(&format!("r.{i}"), i * 8, 50),
            QuotingContext::QuotedString,
        );
    }

    let limited = Bounds {
        max_reasons: 3,
        ..bounds()
    };
    let v = finalize(evidence, limited, attribution());

    let ids: Vec<&str> = v.suppressed().iter().map(|r| r.rule_id()).collect();
    assert_eq!(ids, ["r.0", "r.1", "r.2"], "earliest by offset, truncated");
    assert!(v.suppressions_truncated());
    assert!(
        v.incomplete().is_empty(),
        "truncating the suppressed list is still not a coverage gap"
    );
    assert_eq!(
        v.outcome(),
        Outcome::Clean,
        "and it must not flip the outcome — this is the case suppression exists for"
    );
}

#[test]
fn an_observation_annotated_but_not_suppressed_is_reported_with_its_context() {
    // Acceptance scenario 3: `--no-suppress-in-quotes`. The observation is reported, and it carries the
    // context that WOULD have hidden it — so a reader can tell which findings the heuristic disagrees with
    // them about, in the same run.
    let mut observation = an_observation("override.disregard_prior", 20, 85);
    observation.suppressed_by = Some(QuotingContext::FencedCode);

    let mut evidence = Evidence::new();
    evidence.observe(observation);

    let v = verdict_from(evidence);
    assert_eq!(v.outcome(), Outcome::RiskFound, "it is reported");
    assert_eq!(v.score(), 85, "and it scores");
    assert_eq!(
        v.reasons()[0].suppressed_by(),
        Some(SuppressedBy::Quoting(QuotingContext::FencedCode)),
        "annotated with what would have hidden it"
    );
    assert!(v.suppressed().is_empty(), "nothing was actually suppressed");
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
        severity in 0u8..=100,
    ) {
        let mut evidence = Evidence::new();
        for i in 0..observation_count {
            // Severity varies across the run rather than being fixed at 50: the score is now DERIVED from
            // these, so a constant severity would leave the score half-unexercised. It used to be a separate
            // input to `finalize`; there is nowhere to put one now (FR-127).
            evidence.observe(an_observation(&format!("test.rule_{i}"), i * 8, severity));
        }
        for i in 0..gap_count {
            evidence.record_gap(CoverageGap::bound(
                IncompleteCause::MaxMatchesPerRule,
                i as u64,
                format!("rule `test.rule_{i}` saturated"),
            ));
        }

        let v = finalize(evidence, bounds(), attribution());

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
