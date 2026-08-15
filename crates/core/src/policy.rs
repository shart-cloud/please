//! Caller-owned scan configuration.
//!
//! Every value here belongs to the caller and is **never** derived from scanned content (FR-020). That
//! is not a stylistic point: a policy inferred from the text being analysed is a policy an attacker
//! writes, and the first thing they would turn off is the detector that catches them.
//!
//! Bounds are counted, not timed — bytes, depth, matches — because a wall-clock deadline needs a clock
//! and `std::time::Instant` does not work on `wasm32-unknown-unknown` (research D10). Counted bounds
//! are also deterministic, which SC-011's byte-identical output requires anyway. A wall-clock budget
//! belongs to whoever launched the process.

use crate::finalize::types::{DetectionClass, RiskLevel};

/// Default maximum input size: 1 MiB.
///
/// An order of magnitude above the largest single prompt in the evaluation corpus (82,300 bytes) while
/// staying far below anything that threatens the linear-time budget.
pub const DEFAULT_MAX_INPUT_BYTES: u64 = 1024 * 1024;

/// Default decode depth. Three layers of nesting covers observed obfuscation with room to spare;
/// beyond that the remainder is reported unexamined rather than chased.
pub const DEFAULT_MAX_DECODE_DEPTH: u8 = 3;

/// Default matches collected per rule.
///
/// This is the bound that keeps analysis linear. The matching engine guarantees `O(m·n)` for a single
/// search but `O(m·n²)` for iteration, because each match restarts a search — so an uncapped
/// all-matches scan is quadratic in input length, which is the denial-of-service vector the whole
/// design forbids. Capping at a constant makes it `O(K·m·n)` (research D2).
pub const DEFAULT_MAX_MATCHES_PER_RULE: u32 = 16;

/// Default reasons reported per verdict. Bounded independently of input length (FR-007).
pub const DEFAULT_MAX_REASONS: u32 = 64;

/// Default excerpt length in bytes.
pub const DEFAULT_MAX_EXCERPT_BYTES: u32 = 256;

/// Every detection class, in a stable order.
///
/// Five since T048 removed `Encoding`, which named a delivery mechanism rather than a kind of finding and
/// was the reason class selection did not work — see [`DetectionClass`].
pub const ALL_CLASSES: [DetectionClass; 5] = [
    DetectionClass::Override,
    DetectionClass::Concealment,
    DetectionClass::Confusable,
    DetectionClass::Boundary,
    DetectionClass::Solicitation,
];

/// Configuration governing one scan.
///
/// Defaults are **provisional** pending calibration against per-source corpus metrics, and
/// `docs/limits.md` says so rather than implying a calibration that has not happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScanPolicy {
    /// Inputs larger than this are not analysed; the verdict is inconclusive (FR-017).
    pub max_input_bytes: u64,
    /// Nested decoding stops here, and the unexamined remainder is reported (FR-018).
    pub max_decode_depth: u8,
    /// Matches collected per rule before saturation is recorded (research D2).
    pub max_matches_per_rule: u32,
    /// Reasons reported before truncation is recorded (FR-007).
    pub max_reasons: u32,
    /// Excerpt length before truncation (FR-021).
    pub max_excerpt_bytes: u32,
    /// The band at or above which a caller's tooling treats a verdict as actionable (FR-029).
    ///
    /// The engine records this and reports against it; it does not act on it (FR-006).
    pub threshold: RiskLevel,
    /// Active detection classes (FR-015). Order-insensitive; a `Vec` rather than a set so iteration
    /// order is deterministic (SC-011).
    pub classes: Vec<DetectionClass>,
    /// Whether matches inside quoting contexts are suppressed (FR-014, research D8).
    ///
    /// On by default. Without it the scanner flags documents that *discuss* prompt injection — threat
    /// models, advisories, this repository's own specification — which makes it unusable by the people
    /// most likely to evaluate it. The cost is a real false negative: a payload inside a code fence is
    /// suppressed. That trade is recorded in `docs/limits.md` rather than left to be discovered.
    pub suppress_in_quotes: bool,
}

impl Default for ScanPolicy {
    fn default() -> Self {
        Self {
            max_input_bytes: DEFAULT_MAX_INPUT_BYTES,
            max_decode_depth: DEFAULT_MAX_DECODE_DEPTH,
            max_matches_per_rule: DEFAULT_MAX_MATCHES_PER_RULE,
            max_reasons: DEFAULT_MAX_REASONS,
            max_excerpt_bytes: DEFAULT_MAX_EXCERPT_BYTES,
            threshold: RiskLevel::High,
            classes: ALL_CLASSES.to_vec(),
            suppress_in_quotes: true,
        }
    }
}

impl ScanPolicy {
    /// True when `class` is active under this policy.
    pub fn is_active(&self, class: DetectionClass) -> bool {
        self.classes.contains(&class)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_documented_values() {
        let p = ScanPolicy::default();
        assert_eq!(p.max_input_bytes, 1024 * 1024);
        assert_eq!(p.max_decode_depth, 3);
        assert_eq!(p.max_matches_per_rule, 16);
        assert_eq!(p.max_reasons, 64);
        assert_eq!(p.max_excerpt_bytes, 256);
        assert_eq!(p.threshold, RiskLevel::High);
        assert!(p.suppress_in_quotes);
    }

    #[test]
    fn all_classes_are_active_by_default() {
        let p = ScanPolicy::default();
        for class in ALL_CLASSES {
            assert!(p.is_active(class), "{class:?} should be active by default");
        }
        assert_eq!(p.classes.len(), 5, "ALL_CLASSES must cover every variant");
    }

    #[test]
    fn max_input_default_exceeds_the_largest_corpus_prompt() {
        // The largest single prompt measured in the evaluation corpus is 82,300 bytes
        // (docs/research/corpus-analysis.md). The default must clear it comfortably, or the scanner
        // would report inconclusive on inputs the corpus itself contains.
        assert!(ScanPolicy::default().max_input_bytes > 82_300);
    }
}
