//! Score aggregation (FR-001a, FR-001b).
//!
//! One formula decides every block/allow outcome, so it sets the false-positive rate that the
//! constitution makes a merge gate. These are properties rather than examples because the properties are
//! the reason this formula was chosen over the obvious alternatives:
//!
//! * **Summing** would make score grow with input length, so a long benign engineering document
//!   accumulates innocuous matches until it crosses any threshold. The tool would then behave worst on
//!   the large, important files a team most wants scanned.
//! * **Pure maximum** is length-independent but throws away corroboration, and corroboration is real
//!   signal: an override phrase *and* hidden characters *and* an encoded payload in one file is far more
//!   suspicious than any one alone.
//!
//! Counting **distinct classes** — at most six — buys the corroboration term while keeping the bonus
//! bounded by construction rather than by a tuned cap.

use please_core::score::{aggregate, BONUS_CAP, BONUS_PER_CLASS};
use please_core::verdict::DetectionClass;

/// Every class: six, after 002 removed `Encoding` and 003 added `AgentDirected`.
///
/// Kept as a local constant rather than reading `policy::ALL_CLASSES` so that a change to the class set is a
/// visible edit to this file: the corroboration cap depends on how many classes exist, and it should not
/// change silently underneath a test asserting the cap is reachable.
const ALL: [DetectionClass; 6] = [
    DetectionClass::Override,
    DetectionClass::Concealment,
    DetectionClass::Confusable,
    DetectionClass::Boundary,
    DetectionClass::Solicitation,
    DetectionClass::AgentDirected,
];

/// `(severity, class)` pairs, the shape aggregation consumes.
fn hits(pairs: &[(u8, DetectionClass)]) -> Vec<(u8, DetectionClass)> {
    pairs.to_vec()
}

// ── Ground cases ───────────────────────────────────────────────────────────────────────────────

#[test]
fn no_hits_scores_zero() {
    assert_eq!(aggregate(&[]), 0);
}

#[test]
fn a_single_hit_scores_its_severity() {
    // No corroboration, so no bonus: one finding is worth exactly what its rule says.
    assert_eq!(aggregate(&hits(&[(85, DetectionClass::Override)])), 85);
    assert_eq!(aggregate(&hits(&[(10, DetectionClass::Override)])), 10);
}

// ── The property that rules out summing ────────────────────────────────────────────────────────

#[test]
fn repeated_matches_of_one_class_do_not_raise_the_score() {
    // This is the property that keeps a long benign document from failing on its length. Twenty hits of
    // one class must score exactly as one hit of it.
    let one = aggregate(&hits(&[(60, DetectionClass::Override)]));
    let many = aggregate(&[(60, DetectionClass::Override); 20]);
    assert_eq!(one, many, "score must not grow with match count");
}

#[test]
fn score_is_insensitive_to_input_length() {
    // Expressed as the thing length actually changes: how many matches accumulate. A 50-page document
    // and a one-line snippet with the same worst finding and the same class mix must score identically.
    let short = aggregate(&hits(&[
        (70, DetectionClass::Override),
        (40, DetectionClass::Boundary),
    ]));
    let mut long = Vec::new();
    for _ in 0..500 {
        long.push((70, DetectionClass::Override));
        long.push((40, DetectionClass::Boundary));
    }
    assert_eq!(short, aggregate(&long));
}

// ── The property that rules out pure maximum ───────────────────────────────────────────────────

#[test]
fn additional_distinct_classes_raise_the_score() {
    let one = aggregate(&hits(&[(60, DetectionClass::Override)]));
    let two = aggregate(&hits(&[
        (60, DetectionClass::Override),
        (30, DetectionClass::Concealment),
    ]));
    let three = aggregate(&hits(&[
        (60, DetectionClass::Override),
        (30, DetectionClass::Concealment),
        (20, DetectionClass::Boundary),
    ]));
    assert!(two > one, "corroboration from a second class must count");
    assert!(three > two, "and from a third");
    assert_eq!(two - one, BONUS_PER_CLASS);
}

#[test]
fn the_bonus_is_capped() {
    // Bounded by construction — there are only six classes — and capped besides, so no combination of
    // findings can turn a moderate worst-finding into a critical verdict on breadth alone.
    let all: Vec<(u8, DetectionClass)> = ALL.iter().map(|c| (50, *c)).collect();
    assert_eq!(aggregate(&all), 50 + BONUS_CAP);
}

/// Breadth of evidence may nudge a verdict, never manufacture a severe one out of weak findings.
///
/// A compile-time assertion rather than a runtime one: both sides are constants, so this belongs in the
/// build rather than in a test run, and retuning the bonus during calibration will fail to compile
/// rather than fail a test somebody might skip.
const _: () = assert!(
    BONUS_CAP < 50,
    "the corroboration bonus must never dominate the worst single finding"
);

// ── Bounds ─────────────────────────────────────────────────────────────────────────────────────

#[test]
fn score_never_exceeds_one_hundred() {
    let all: Vec<(u8, DetectionClass)> = ALL.iter().map(|c| (100, *c)).collect();
    assert_eq!(aggregate(&all), 100);
}

#[test]
fn a_zero_severity_hit_still_counts_as_a_class() {
    // A rule with severity zero is a reporting rule, not a scoring one — but it is still evidence of a
    // class being present, so it may contribute corroboration to something else.
    let alone = aggregate(&hits(&[(0, DetectionClass::Override)]));
    assert_eq!(alone, 0);
    let with_other = aggregate(&hits(&[
        (0, DetectionClass::Override),
        (50, DetectionClass::Boundary),
    ]));
    assert_eq!(with_other, 50 + BONUS_PER_CLASS);
}

// ── Order independence ─────────────────────────────────────────────────────────────────────────

#[test]
fn score_is_independent_of_hit_order() {
    // Required by byte-identical output (SC-011): reasons are sorted by offset, and a caller must get
    // the same score whichever order the detectors happened to run in.
    let forward = aggregate(&hits(&[
        (30, DetectionClass::Concealment),
        (70, DetectionClass::Override),
        (50, DetectionClass::Boundary),
    ]));
    let reverse = aggregate(&hits(&[
        (50, DetectionClass::Boundary),
        (70, DetectionClass::Override),
        (30, DetectionClass::Concealment),
    ]));
    assert_eq!(forward, reverse);
}

// ── Properties over generated input ────────────────────────────────────────────────────────────

proptest::proptest! {
    /// The score is always at least the worst single severity, and never more than that plus the cap.
    ///
    /// Stated as a two-sided bound rather than an equality so it keeps holding if the bonus term is
    /// retuned during calibration.
    #[test]
    fn score_is_bracketed_by_the_worst_finding(
        raw in proptest::collection::vec((0u8..=100, 0usize..ALL.len()), 0..40),
    ) {
        let pairs: Vec<(u8, DetectionClass)> =
            raw.iter().map(|(sev, idx)| (*sev, ALL[*idx])).collect();
        let score = aggregate(&pairs);

        match pairs.iter().map(|(s, _)| *s).max() {
            None => proptest::prop_assert_eq!(score, 0),
            Some(worst) => {
                proptest::prop_assert!(
                    score >= worst,
                    "score {} below worst severity {}", score, worst,
                );
                proptest::prop_assert!(
                    score <= worst.saturating_add(BONUS_CAP),
                    "score {} exceeds worst {} plus cap {}", score, worst, BONUS_CAP,
                );
                proptest::prop_assert!(score <= 100);
            }
        }
    }

    /// Duplicating every hit changes nothing. The count-insensitivity property, over arbitrary input.
    #[test]
    fn duplicating_hits_does_not_change_the_score(
        raw in proptest::collection::vec((0u8..=100, 0usize..ALL.len()), 1..20),
    ) {
        let pairs: Vec<(u8, DetectionClass)> =
            raw.iter().map(|(sev, idx)| (*sev, ALL[*idx])).collect();
        let doubled: Vec<(u8, DetectionClass)> =
            pairs.iter().chain(pairs.iter()).copied().collect();
        proptest::prop_assert_eq!(aggregate(&pairs), aggregate(&doubled));
    }

    /// Adding a hit never lowers the score. Monotonicity keeps the threshold comparison meaningful: a
    /// caller must not be able to reduce a verdict's risk by finding more wrong with the input.
    #[test]
    fn adding_a_hit_never_lowers_the_score(
        raw in proptest::collection::vec((0u8..=100, 0usize..ALL.len()), 0..20),
        extra in (0u8..=100, 0usize..ALL.len()),
    ) {
        let pairs: Vec<(u8, DetectionClass)> =
            raw.iter().map(|(sev, idx)| (*sev, ALL[*idx])).collect();
        let before = aggregate(&pairs);
        let mut after_pairs = pairs.clone();
        after_pairs.push((extra.0, ALL[extra.1]));
        proptest::prop_assert!(aggregate(&after_pairs) >= before);
    }
}
