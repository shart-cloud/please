//! The invariant everything else rests on: a clean verdict means the whole input was examined.
//!
//! If these tests pass and nothing else does, the tool is still honest — it will say "I could not
//! tell" instead of "this is fine". If these fail and everything else passes, the tool is worse than
//! absent, because it reports safety it never established.
//!
//! Written before [`Verdict::assemble`] is implemented (T014–T016 precede T017), against a stub that
//! always reports clean. Every assertion here is expected to fail on first run.

use please_core::verdict::{
    EngineId, IncompleteCause, Incompleteness, Outcome, RiskLevel, RulesetId, TargetRef, Verdict,
    VerdictParts,
};
use please_core::{DetectionClass, Reason, Span};

fn ruleset() -> RulesetId {
    RulesetId {
        name: "test.fixture".to_string(),
        version: "0.0.0".to_string(),
        digest: "0000000000000000".to_string(),
    }
}

fn parts() -> VerdictParts {
    VerdictParts {
        score: 0,
        risk: RiskLevel::None,
        reasons: Vec::new(),
        reasons_truncated: false,
        incomplete: Vec::new(),
        target: TargetRef::buffer("test", 0),
        ruleset: ruleset(),
        engine: EngineId::current(),
    }
}

fn a_reason(rule_id: &str, start: usize, severity: u8) -> Reason {
    Reason {
        rule_id: rule_id.to_string(),
        class: DetectionClass::Override,
        span: Span::new(start, start + 4),
        matched: "test".to_string(),
        severity,
        chain: Vec::new(),
        description: "test rule".to_string(),
        suppressed_by: None,
    }
}

// ── T014: clean requires BOTH accumulators empty ────────────────────────────────────────────────

#[test]
fn clean_when_nothing_found_and_nothing_unexamined() {
    let v = Verdict::assemble(parts());
    assert_eq!(v.outcome(), Outcome::Clean);
    assert_eq!(v.score(), 0);
}

#[test]
fn not_clean_when_a_bound_was_hit_even_with_no_reasons() {
    // The whole fail-closed posture in one assertion. An oversized input found nothing *because it
    // was never looked at*, and reporting that as clean is the failure this project exists to avoid.
    let v = Verdict::assemble(VerdictParts {
        incomplete: vec![Incompleteness::bound(IncompleteCause::InputSize, 1_048_576)],
        ..parts()
    });
    assert_eq!(
        v.outcome(),
        Outcome::Inconclusive,
        "a scan that hit a bound must never be clean"
    );
}

#[test]
fn not_clean_when_a_target_was_unreadable() {
    let v = Verdict::assemble(VerdictParts {
        incomplete: vec![Incompleteness::failure(
            IncompleteCause::TargetUnreadable,
            "permission denied",
        )],
        ..parts()
    });
    assert_eq!(v.outcome(), Outcome::Inconclusive);
}

#[test]
fn not_clean_when_an_optional_tier_was_unavailable() {
    // Principle I: an unavailable tier degrades to inconclusive, never to clean. A caller may choose
    // to treat that as passing; the engine must not choose for them.
    let v = Verdict::assemble(VerdictParts {
        incomplete: vec![Incompleteness::failure(
            IncompleteCause::TierUnavailable,
            "classifier tier not built",
        )],
        ..parts()
    });
    assert_eq!(v.outcome(), Outcome::Inconclusive);
}

#[test]
fn risk_found_when_a_rule_fired() {
    let v = Verdict::assemble(VerdictParts {
        score: 85,
        risk: RiskLevel::High,
        reasons: vec![a_reason("override.ignore_previous", 10, 85)],
        ..parts()
    });
    assert_eq!(v.outcome(), Outcome::RiskFound);
}

#[test]
fn clean_verdict_carries_zero_score() {
    // A clean verdict with a non-zero score would be incoherent: the score exists to summarise
    // findings, and there are none.
    let v = Verdict::assemble(VerdictParts {
        score: 42,
        risk: RiskLevel::Low,
        ..parts()
    });
    assert_eq!(v.outcome(), Outcome::Clean);
    assert_eq!(v.score(), 0, "a clean verdict must report score 0");
    assert_eq!(v.risk(), RiskLevel::None);
}

// ── T016: precedence ───────────────────────────────────────────────────────────────────────────

#[test]
fn risk_found_outranks_inconclusive() {
    // Found a real payload AND ran out of budget. Reporting inconclusive would discard a confirmed
    // detection; the verdict is risk_found and carries the gap so the caller knows there may be more.
    let v = Verdict::assemble(VerdictParts {
        score: 85,
        risk: RiskLevel::High,
        reasons: vec![a_reason("override.ignore_previous", 10, 85)],
        incomplete: vec![Incompleteness::bound(IncompleteCause::MaxReasons, 64)],
        reasons_truncated: true,
        ..parts()
    });
    assert_eq!(v.outcome(), Outcome::RiskFound);
    assert!(v.is_incomplete(), "the coverage gap must still be visible");
    assert!(v.reasons_truncated());
}

#[test]
fn outcome_rank_orders_risk_above_inconclusive_above_clean() {
    assert!(Outcome::RiskFound.rank() > Outcome::Inconclusive.rank());
    assert!(Outcome::Inconclusive.rank() > Outcome::Clean.rank());
}

// ── T015: the invariant holds for arbitrary evidence ───────────────────────────────────────────

proptest::proptest! {
    /// For any combination of reasons and coverage gaps, `Clean` implies both are empty.
    ///
    /// Stated as an implication rather than a case analysis so that it keeps holding when a seventh
    /// `IncompleteCause` or an eighth field arrives.
    #[test]
    fn clean_implies_nothing_found_and_nothing_missed(
        reason_count in 0usize..6,
        gap_count in 0usize..6,
        score in 0u8..=100,
    ) {
        let reasons: Vec<Reason> = (0..reason_count)
            .map(|i| a_reason(&format!("test.rule_{i}"), i * 8, 50))
            .collect();
        let incomplete: Vec<Incompleteness> = (0..gap_count)
            .map(|i| Incompleteness::bound(IncompleteCause::MaxMatchesPerRule, i as u64))
            .collect();

        let v = Verdict::assemble(VerdictParts {
            score,
            risk: RiskLevel::Medium,
            reasons,
            incomplete,
            ..parts()
        });

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

// ── Structural guarantee ───────────────────────────────────────────────────────────────────────

#[test]
fn verdict_cannot_be_constructed_outside_assemble() {
    // Not a runtime assertion — a note about why the fields are private. If `Verdict`'s fields were
    // public, a detector could build `Verdict { outcome: Clean, incomplete: vec![..], .. }` and every
    // test above would still pass while the invariant was broken in production. The single
    // constructor is what makes the invariant an invariant rather than a convention.
    //
    // Uncommenting the following must fail to compile:
    //
    //   let _ = Verdict { outcome: Outcome::Clean, .. };
    //
    // Verified by the accessors being the only read path:
    let v = Verdict::assemble(parts());
    let _ = (
        v.outcome(),
        v.score(),
        v.risk(),
        v.reasons(),
        v.incomplete(),
    );
}
