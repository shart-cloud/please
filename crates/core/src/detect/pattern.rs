//! Pattern evaluation: lazy compilation, memoised, with a hard cap on matches collected.
//!
//! # The cap is not a performance tweak
//!
//! The matching engine guarantees `O(m·n)` for a *single* search, but its iterators are `O(m·n²)`
//! because each match restarts a search from the previous end. A scanner wants every match, so the
//! obvious `find_iter`-per-rule loop is **quadratic in input length** — which on the 82 KB inputs the
//! evaluation corpus already contains is precisely the denial-of-service vector Principle II forbids,
//! introduced by the detector itself rather than by an attacker's cleverness.
//!
//! Capping collection at a constant `K` makes the per-rule cost `O(K·m·n)`, linear in `n`. The same cap
//! is what FR-007 independently requires for bounded reasons, so one mechanism discharges FR-007,
//! FR-016, and SC-005 together. When it bites, the verdict says so — a bound the reader cannot see reads
//! as complete coverage.
//!
//! # Bytes, not `&str`
//!
//! Matching runs on `regex::bytes`, so a rule can still fire either side of a malformed sequence.
//! Requiring valid UTF-8 would mean either rejecting an input or lossily rewriting it before analysis,
//! and "this was not valid text" is a fact to report rather than a reason to stop looking (FR-019).
//! Spans are therefore byte offsets into the original input, which is what [`Span`] already means.

use std::sync::OnceLock;

use regex::bytes::{Regex, RegexBuilder};

use crate::ruleset::{Rule, RulesetLimits};
use crate::verdict::Span;

/// Outcome of evaluating one rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleMatches {
    /// Byte spans in the input, in order of occurrence.
    pub spans: Vec<Span>,
    /// True when the match cap stopped collection, so there may be further matches unreported.
    pub saturated: bool,
}

/// Why a rule could not be evaluated.
///
/// Never silently skipped. A rule that failed to compile is a gap in coverage, and a gap in coverage
/// that nothing records is the fail-open this project exists to close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleUnavailable {
    pub rule_id: String,
    pub detail: String,
}

/// Lazily compiled patterns for one rule set.
///
/// Compilation is memoised and **never invalidated**, so a scan's result cannot depend on how many
/// scans preceded it — which FR-020 requires and FR-030 makes observable.
#[derive(Debug)]
pub struct PatternSet {
    /// One slot per rule, indexed to match the rule slice this was built from.
    ///
    /// `OnceLock` rather than a lock around a map: initialisation happens at most once per rule, reads
    /// afterwards are uncontended, and the type makes "compiled at most once" a property of the
    /// structure rather than of the code that uses it.
    slots: Vec<OnceLock<Result<Regex, String>>>,
    limits: RulesetLimits,
}

impl PatternSet {
    pub fn new(rule_count: usize, limits: RulesetLimits) -> Self {
        Self {
            slots: (0..rule_count).map(|_| OnceLock::new()).collect(),
            limits,
        }
    }

    /// Compile on first use; return the memoised result afterwards.
    fn regex_for(&self, index: usize, rule: &Rule) -> Result<&Regex, &String> {
        self.slots[index]
            .get_or_init(|| {
                RegexBuilder::new(&rule.pattern)
                    .size_limit(self.limits.max_compiled_bytes)
                    .build()
                    .map_err(|e| e.to_string())
            })
            .as_ref()
    }

    /// Evaluate one rule, collecting at most `max_matches` spans.
    ///
    /// Returns `Err` when the pattern cannot be compiled. That should be unreachable for a rule set that
    /// passed `validate_compiled`, but it is returned rather than ignored so the caller can record it as
    /// a coverage gap instead of treating the rule as having found nothing.
    pub fn matches(
        &self,
        index: usize,
        rule: &Rule,
        haystack: &[u8],
        max_matches: u32,
    ) -> Result<RuleMatches, RuleUnavailable> {
        let regex = self
            .regex_for(index, rule)
            .map_err(|detail| RuleUnavailable {
                rule_id: rule.id.clone(),
                detail: detail.clone(),
            })?;

        if max_matches == 0 {
            // A cap of zero means "collect nothing", which is still a saturated collection rather than
            // an absence of matches — reporting it as clean would be a lie about coverage.
            return Ok(RuleMatches {
                spans: Vec::new(),
                saturated: regex.is_match(haystack),
            });
        }

        let limit = max_matches as usize;
        let mut spans = Vec::new();
        let mut saturated = false;

        // `take(limit + 1)` rather than `take(limit)`: pulling one extra element is how we learn whether
        // there was more to find, without scanning the remainder of the input.
        for found in regex.find_iter(haystack).take(limit + 1) {
            if spans.len() == limit {
                saturated = true;
                break;
            }
            spans.push(Span::new(found.start(), found.end()));
        }

        Ok(RuleMatches { spans, saturated })
    }

    /// True when this rule's pattern has already been compiled.
    ///
    /// Exposed for tests that assert the gate actually prevents compilation, which is the claim the
    /// latency budget rests on.
    pub fn is_compiled(&self, index: usize) -> bool {
        self.slots[index].get().is_some()
    }

    pub fn len(&self) -> usize {
        self.slots.len()
    }

    pub fn is_empty(&self) -> bool {
        self.slots.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verdict::DetectionClass;

    fn rule(id: &str, pattern: &str) -> Rule {
        Rule {
            id: id.to_string(),
            class: DetectionClass::Override,
            severity: 50,
            literals: vec!["x".to_string()],
            pattern: pattern.to_string(),
            fires_in_quotes: false,
            enabled: true,
            description: "test".to_string(),
        }
    }

    fn set() -> PatternSet {
        PatternSet::new(2, RulesetLimits::default())
    }

    #[test]
    fn a_matching_rule_reports_its_spans() {
        let r = rule("a.one", "needle");
        let got = set().matches(0, &r, b"a needle here", 16).unwrap();
        assert_eq!(got.spans, vec![Span::new(2, 8)]);
        assert!(!got.saturated);
    }

    #[test]
    fn a_non_matching_rule_reports_nothing() {
        let r = rule("a.one", "needle");
        let got = set().matches(0, &r, b"nothing relevant", 16).unwrap();
        assert!(got.spans.is_empty());
        assert!(!got.saturated);
    }

    #[test]
    fn collection_stops_at_the_cap_and_says_so() {
        let r = rule("a.one", "ab");
        let haystack = "ab".repeat(100);
        let got = set().matches(0, &r, haystack.as_bytes(), 5).unwrap();
        assert_eq!(got.spans.len(), 5, "must not collect beyond the cap");
        assert!(got.saturated, "saturation must be reported, not silent");
    }

    #[test]
    fn exactly_the_cap_many_matches_is_not_saturated() {
        // The off-by-one that matters: reporting saturation when nothing was dropped would put a
        // spurious coverage gap on a complete scan, and every such gap turns a clean verdict
        // inconclusive.
        let r = rule("a.one", "ab");
        let haystack = "ab".repeat(5);
        let got = set().matches(0, &r, haystack.as_bytes(), 5).unwrap();
        assert_eq!(got.spans.len(), 5);
        assert!(!got.saturated);
    }

    #[test]
    fn a_zero_cap_still_reports_saturation_when_the_rule_would_match() {
        let r = rule("a.one", "needle");
        let got = set().matches(0, &r, b"a needle here", 0).unwrap();
        assert!(got.spans.is_empty());
        assert!(
            got.saturated,
            "collecting nothing is not the same as finding nothing"
        );

        let got = set().matches(0, &r, b"no match at all", 0).unwrap();
        assert!(!got.saturated);
    }

    #[test]
    fn compilation_is_lazy_and_memoised() {
        // The claim the latency budget rests on: an unevaluated rule costs nothing.
        let s = set();
        let r = rule("a.one", "needle");
        assert!(!s.is_compiled(0), "must not compile before first use");
        let _ = s.matches(0, &r, b"needle", 16).unwrap();
        assert!(s.is_compiled(0));
        assert!(!s.is_compiled(1), "an untouched rule stays uncompiled");
    }

    #[test]
    fn repeated_evaluation_is_stable() {
        // Memoisation must not make a verdict depend on scan history (FR-020, FR-030).
        let s = set();
        let r = rule("a.one", "needle");
        let first = s.matches(0, &r, b"a needle here", 16).unwrap();
        let second = s.matches(0, &r, b"a needle here", 16).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn an_uncompilable_pattern_is_reported_not_ignored() {
        // Reached only if a rule set skipped `validate_compiled`. It must surface as a coverage gap,
        // never as "this rule found nothing".
        let r = rule("a.one", "(unclosed");
        let err = set().matches(0, &r, b"anything", 16).unwrap_err();
        assert_eq!(err.rule_id, "a.one");
        assert!(!err.detail.is_empty());
    }

    #[test]
    fn a_size_bomb_is_reported_at_match_time_if_it_reached_here() {
        let limits = RulesetLimits {
            max_compiled_bytes: 4096,
            ..RulesetLimits::default()
        };
        let s = PatternSet::new(1, limits);
        let r = rule("a.one", "a{1000}{1000}{1000}");
        assert!(s.matches(0, &r, b"aaaa", 16).is_err());
    }

    #[test]
    fn matching_works_across_invalid_utf8() {
        let r = rule("a.one", "needle");
        let prefix: &[u8] = b"\xff\xfe ";
        let mut haystack = prefix.to_vec();
        haystack.extend_from_slice(b"needle");
        haystack.push(0xff);
        let got = set().matches(0, &r, &haystack, 16).unwrap();
        assert_eq!(got.spans.len(), 1);
        assert_eq!(
            got.spans[0].start,
            prefix.len(),
            "span is a byte offset into the original input, counting the malformed prefix"
        );
        assert_eq!(got.spans[0].end, prefix.len() + "needle".len());
    }
}
