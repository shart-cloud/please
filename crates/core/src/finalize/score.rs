//! Score aggregation and banding (FR-001a, FR-001b).
//!
//! ```text
//! score = min(100, max_severity + min(BONUS_CAP, BONUS_PER_CLASS × (distinct_classes − 1)))
//! ```
//!
//! One formula decides every block/allow outcome, so it sets the false-positive rate the constitution
//! makes a merge gate. Three properties motivate it, each corresponding to a way an obvious alternative
//! fails:
//!
//! * **Insensitive to input length.** A summed score rises as a document grows, so a long benign
//!   engineering document accumulates innocuous matches until it crosses any threshold — the tool would
//!   behave worst on exactly the large, important files a team most wants scanned.
//! * **Insensitive to match count.** Twenty matches of one rule score exactly as one. Only *distinct
//!   classes* add, and there are at most six, so the bonus is bounded by construction rather than by a
//!   cap somebody has to tune.
//! * **Rewards corroboration.** An override phrase plus concealment plus a forged role marker is genuinely
//!   more suspicious than any alone, and this is the term that says so. Pure maximum discards it.
//!
//! Note what corroboration now means, after `Encoding` was removed as a class: breadth across *kinds of
//! finding*, not across delivery routes. An override phrase that arrived base-64'd used to contribute two
//! classes to this sum — `Override` for the clear copy and `Encoding` for the decoded one — which rewarded
//! the same finding twice for having been obfuscated. The obfuscation is still evidence, and it is still
//! recorded, in the transformation chain where it belongs.
//!
//! # Aggregate before truncating
//!
//! Aggregation runs over **every** match found, not over the reasons that survive `max_reasons`. Reasons
//! are ordered by byte offset for reproducibility, not by severity, so truncating first could discard
//! the highest-severity finding and understate the score (FR-001b).
//!
//! # These constants are not calibrated
//!
//! They are chosen. Calibration needs the evaluation harness and a real corpus; until then
//! `docs/limits.md` says so rather than implying a rigour that does not exist. The properties above are
//! what the tests pin down, so retuning these numbers during calibration will not silently change the
//! formula's character.

use super::types::DetectionClass;

/// Added per distinct detection class beyond the highest-scoring one.
pub const BONUS_PER_CLASS: u8 = 5;

/// Ceiling on the total corroboration bonus.
///
/// Deliberately far below a band's width: breadth of evidence should be able to nudge a verdict, never
/// to manufacture a critical finding out of a handful of weak ones.
pub const BONUS_CAP: u8 = 15;

/// Aggregate `(severity, class)` hits into a single score on `0..=100`.
///
/// Order-independent and duplicate-insensitive, both of which the property tests assert.
pub fn aggregate(hits: &[(u8, DetectionClass)]) -> u8 {
    if hits.is_empty() {
        return 0;
    }

    let worst = hits
        .iter()
        .map(|(severity, _)| *severity)
        .max()
        .unwrap_or(0);

    // Count distinct classes without allocating a set: there are at most six, so a fixed-size flag
    // array is both smaller and deterministic — a hash set would introduce iteration order that
    // byte-identical output cannot afford (SC-011).
    let mut present = [false; CLASS_COUNT];
    for (_, class) in hits {
        present[class_index(*class)] = true;
    }
    let distinct = present.iter().filter(|p| **p).count() as u8;

    let bonus = BONUS_PER_CLASS
        .saturating_mul(distinct.saturating_sub(1))
        .min(BONUS_CAP);

    worst.saturating_add(bonus).min(100)
}

/// Number of detection classes, and the width of the corroboration array.
///
/// Seven. This constant and [`class_index`] below are why changing the `DetectionClass` set is a compile
/// error rather than a silent change in scoring — see the note on the wildcard arm. It has now caught the
/// guard three times: 002 removing `Encoding`, 003 adding `AgentDirected`, and the actionable-directive
/// measurement adding `ExternalAction`.
const CLASS_COUNT: usize = 7;

/// Stable index for the fixed-size presence array.
///
/// Deliberately **exhaustive with no wildcard arm**. [`DetectionClass`] is `non_exhaustive` for
/// downstream crates, but inside this one every variant is known — so adding a seventh class makes this
/// function fail to compile, which is exactly the right outcome. A wildcard here would let a new class
/// silently contribute no corroboration bonus, and a scoring term that quietly stops applying is the
/// kind of bug that shows up as a drifting false-negative rate months later.
fn class_index(class: DetectionClass) -> usize {
    match class {
        DetectionClass::Override => 0,
        DetectionClass::Concealment => 1,
        DetectionClass::Confusable => 2,
        DetectionClass::Boundary => 3,
        DetectionClass::Solicitation => 4,
        DetectionClass::AgentDirected => 5,
        DetectionClass::ExternalAction => 6,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_class_has_a_distinct_slot_within_the_array() {
        // Exhaustiveness is enforced by the compiler (see `class_index`). What that cannot catch is two
        // classes sharing a slot, which would silently merge them for corroboration purposes.
        let mut seen = Vec::new();
        for class in crate::policy::ALL_CLASSES {
            let slot = class_index(class);
            assert!(
                slot < CLASS_COUNT,
                "{class:?} slot {slot} outside the array"
            );
            assert!(!seen.contains(&slot), "{class:?} reuses slot {slot}");
            seen.push(slot);
        }
        assert_eq!(seen.len(), CLASS_COUNT, "ALL_CLASSES must cover the array");
    }

    #[test]
    fn saturating_arithmetic_holds_at_the_extremes() {
        // Worst severity already at the ceiling, plus a full corroboration bonus, must clamp rather
        // than wrap.
        assert_eq!(aggregate(&[(100, DetectionClass::Override)]), 100);
        let saturated: Vec<(u8, DetectionClass)> = crate::policy::ALL_CLASSES
            .iter()
            .map(|class| (100, *class))
            .collect();
        assert_eq!(aggregate(&saturated), 100);
    }
}
