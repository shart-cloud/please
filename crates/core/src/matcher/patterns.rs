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

use crate::finalize::evidence::{CoverageGap, Evidence};
use crate::finalize::types::{IncompleteCause, Span};
use crate::ruleset::{Rule, RulesetLimits};

/// Lazily compiled patterns for one rule set.
///
/// Compilation is memoised and **never invalidated**, so a scan's result cannot depend on how many
/// scans preceded it — which FR-020 requires and FR-030 makes observable.
#[derive(Debug)]
pub(super) struct PatternSet {
    /// One slot per rule, indexed to match the rule slice this was built from.
    ///
    /// `OnceLock` rather than a lock around a map: initialisation happens at most once per rule, reads
    /// afterwards are uncontended, and the type makes "compiled at most once" a property of the
    /// structure rather than of the code that uses it.
    slots: Vec<OnceLock<Result<Regex, String>>>,
    limits: RulesetLimits,
}

impl PatternSet {
    /// An empty store, one lazy slot per rule.
    ///
    /// Test-only since T074. Production always arrives through [`prefilled`](Self::prefilled), because
    /// preparation always has something to say about what it compiled — even when the answer is "nothing, the
    /// CI record covers these". A second production constructor would be a second answer to that.
    #[cfg(test)]
    pub(super) fn new(rule_count: usize, limits: RulesetLimits) -> Self {
        Self {
            slots: (0..rule_count).map(|_| OnceLock::new()).collect(),
            limits,
        }
    }

    /// Build with slots already filled by validation (FR-109, SC-106).
    ///
    /// Proving a caller-supplied pattern safe compiles it, and 001 threw that compiled form away and paid
    /// for it again lazily on first match. `retained` carries it across: `Some` slots are sealed here and
    /// never recompiled, `None` slots stay lazy, which is what keeps the eighty built-in rules a given
    /// input does not mention out of the cold-start path.
    ///
    /// The two kinds of slot are why this is one structure with a mixed fill rather than two structures.
    /// Whether a pattern arrives pre-compiled is a property of where its rule came from, not of how the
    /// matcher works, and the matcher should not have to care.
    pub(super) fn prefilled(retained: Vec<Option<Regex>>, limits: RulesetLimits) -> Self {
        let slots: Vec<OnceLock<Result<Regex, String>>> = retained
            .into_iter()
            .map(|compiled| {
                let slot = OnceLock::new();
                if let Some(regex) = compiled {
                    // Cannot fail: a fresh `OnceLock` is empty. `let _` rather than `expect` because the
                    // error case would hand back the `Regex` we just tried to store, and there is nothing
                    // useful to say about a branch that cannot be taken.
                    let _ = slot.set(Ok(regex));
                }
                slot
            })
            .collect();
        Self { slots, limits }
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
    /// Records its own coverage gaps (T022, FR-122). 001 returned `RuleMatches { spans, saturated }` and
    /// a `RuleUnavailable` error, and `engine.rs` turned both into `Incompleteness` values — which is the
    /// translation FR-122 removes. Two things improve by moving it here:
    ///
    ///  * **saturation is reported per rule.** The caller used to collect saturated rule ids and emit one
    ///    gap with them comma-joined, so a reader got `saturated: a, b, c` and no configured value per
    ///    rule. Each rule now records its own, which is more to read and the right amount to read.
    ///  * **a compile failure keeps the compiler's message.** The old site called `.with_detail(..)` on a
    ///    failure that already had a detail, and `with_detail` overwrites — so the actual reason the
    ///    pattern would not build was constructed and then discarded, leaving only "rule `x` could not be
    ///    compiled". Unreachable in principle for a validated rule set, which is exactly why the one time
    ///    it fires you want the message.
    ///
    /// Returns the spans found; an empty vector for a rule that could not be compiled. There is no `Err`
    /// for a caller to translate, because the gap is already recorded — and no way to treat an
    /// uncompilable rule as a rule that found nothing, because those two now differ in the evidence.
    pub(super) fn matches(
        &self,
        index: usize,
        rule: &Rule,
        haystack: &[u8],
        max_matches: u32,
        evidence: &mut Evidence,
    ) -> Vec<Span> {
        let regex = match self.regex_for(index, rule) {
            Ok(regex) => regex,
            Err(detail) => {
                // Never silently skipped. A rule that failed to compile is a gap in coverage, and a gap in
                // coverage that nothing records is the fail-open this project exists to close.
                evidence.record_gap(CoverageGap::failure(
                    IncompleteCause::RulesetUnavailable,
                    format!("rule `{}` could not be compiled: {detail}", rule.id),
                ));
                return Vec::new();
            }
        };

        if max_matches == 0 {
            // A cap of zero means "collect nothing", which is still a saturated collection rather than an
            // absence of matches — reporting it as clean would be a lie about coverage.
            if regex.is_match(haystack) {
                record_saturation(evidence, rule, max_matches);
            }
            return Vec::new();
        }

        let limit = max_matches as usize;
        let mut spans = Vec::new();

        // `take(limit + 1)` rather than `take(limit)`: pulling one extra element is how we learn whether
        // there was more to find, without scanning the remainder of the input.
        for found in regex.find_iter(haystack).take(limit + 1) {
            if spans.len() == limit {
                record_saturation(evidence, rule, max_matches);
                break;
            }
            spans.push(Span::new(found.start(), found.end()));
        }

        spans
    }

    /// True when this rule's pattern has already been compiled.
    ///
    /// Exposed for tests that assert the gate actually prevents compilation, which is the claim the
    /// latency budget rests on.
    pub(super) fn is_compiled(&self, index: usize) -> bool {
        self.slots[index].get().is_some()
    }
}

/// Record that a rule's match cap stopped collection.
///
/// Separate from [`PatternSet::matches`] only because it is recorded from two branches — the ordinary cap
/// and the zero cap — and a reader should be able to see at a glance that both say the same thing.
fn record_saturation(evidence: &mut Evidence, rule: &Rule, max_matches: u32) {
    evidence.record_gap(CoverageGap::bound(
        IncompleteCause::MaxMatchesPerRule,
        max_matches as u64,
        format!("rule `{}` saturated", rule.id),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalize::types::DetectionClass;

    fn rule(id: &str, pattern: &str) -> Rule {
        Rule {
            id: id.to_string(),
            class: DetectionClass::Override,
            severity: 50,
            literals: vec!["x".to_string()],
            pattern: pattern.to_string(),
            fires_in_quotes: false,
            anchor: crate::Anchor::Anywhere,
            enabled: true,
            description: "test".to_string(),
            provenance: crate::prepare::Provenance::supplied(),
        }
    }

    fn set() -> PatternSet {
        PatternSet::new(2, RulesetLimits::default())
    }

    /// The causes recorded during one evaluation.
    ///
    /// Asserting on causes rather than on a `saturated` boolean is the point of T022: what the caller used
    /// to receive was a flag it had to interpret, and what it receives now is the interpretation.
    fn causes(evidence: &Evidence) -> Vec<IncompleteCause> {
        evidence.recorded_gaps().iter().map(|g| g.cause()).collect()
    }

    #[test]
    fn a_matching_rule_reports_its_spans() {
        let r = rule("a.one", "needle");
        let mut evidence = Evidence::new();
        let spans = set().matches(0, &r, b"a needle here", 16, &mut evidence);
        assert_eq!(spans, vec![Span::new(2, 8)]);
        assert!(causes(&evidence).is_empty(), "nothing went unexamined");
    }

    #[test]
    fn a_non_matching_rule_reports_nothing() {
        let r = rule("a.one", "needle");
        let mut evidence = Evidence::new();
        let spans = set().matches(0, &r, b"nothing relevant", 16, &mut evidence);
        assert!(spans.is_empty());
        assert!(causes(&evidence).is_empty());
    }

    #[test]
    fn collection_stops_at_the_cap_and_says_so() {
        let r = rule("a.one", "ab");
        let haystack = "ab".repeat(100);
        let mut evidence = Evidence::new();
        let spans = set().matches(0, &r, haystack.as_bytes(), 5, &mut evidence);
        assert_eq!(spans.len(), 5, "must not collect beyond the cap");
        assert_eq!(
            causes(&evidence),
            [IncompleteCause::MaxMatchesPerRule],
            "saturation must be recorded, not silent"
        );
    }

    #[test]
    fn a_saturation_gap_names_the_rule_and_the_cap_that_stopped_it() {
        // The information the old comma-joined list could not carry. A caller raising a limit needs to
        // know which rule to raise it for and what it currently is.
        let r = rule("a.one", "ab");
        let haystack = "ab".repeat(100);
        let mut evidence = Evidence::new();
        let _ = set().matches(0, &r, haystack.as_bytes(), 5, &mut evidence);
        let gap = &evidence.recorded_gaps()[0];
        assert_eq!(gap.detail(), Some("rule `a.one` saturated"));
    }

    #[test]
    fn exactly_the_cap_many_matches_is_not_saturated() {
        // The off-by-one that matters: reporting saturation when nothing was dropped would put a spurious
        // coverage gap on a complete scan, and every such gap turns a clean verdict inconclusive.
        let r = rule("a.one", "ab");
        let haystack = "ab".repeat(5);
        let mut evidence = Evidence::new();
        let spans = set().matches(0, &r, haystack.as_bytes(), 5, &mut evidence);
        assert_eq!(spans.len(), 5);
        assert!(causes(&evidence).is_empty());
    }

    #[test]
    fn a_zero_cap_still_reports_saturation_when_the_rule_would_match() {
        let r = rule("a.one", "needle");
        let mut evidence = Evidence::new();
        let spans = set().matches(0, &r, b"a needle here", 0, &mut evidence);
        assert!(spans.is_empty());
        assert_eq!(
            causes(&evidence),
            [IncompleteCause::MaxMatchesPerRule],
            "collecting nothing is not the same as finding nothing"
        );

        let mut evidence = Evidence::new();
        let _ = set().matches(0, &r, b"no match at all", 0, &mut evidence);
        assert!(causes(&evidence).is_empty());
    }

    #[test]
    fn compilation_is_lazy_and_memoised() {
        // The claim the latency budget rests on: an unevaluated rule costs nothing.
        let s = set();
        let r = rule("a.one", "needle");
        let mut evidence = Evidence::new();
        assert!(!s.is_compiled(0), "must not compile before first use");
        let _ = s.matches(0, &r, b"needle", 16, &mut evidence);
        assert!(s.is_compiled(0));
        assert!(!s.is_compiled(1), "an untouched rule stays uncompiled");
    }

    #[test]
    fn repeated_evaluation_is_stable() {
        // Memoisation must not make a verdict depend on scan history (FR-020, FR-030).
        let s = set();
        let r = rule("a.one", "needle");
        let mut evidence = Evidence::new();
        let first = s.matches(0, &r, b"a needle here", 16, &mut evidence);
        let second = s.matches(0, &r, b"a needle here", 16, &mut evidence);
        assert_eq!(first, second);
    }

    #[test]
    fn an_uncompilable_pattern_is_reported_not_ignored() {
        // Reached only if a rule set reached an engine without compiled validation — which US1 makes
        // unreachable. It must surface as a coverage gap, never as "this rule found nothing".
        let r = rule("a.one", "(unclosed");
        let mut evidence = Evidence::new();
        let spans = set().matches(0, &r, b"anything", 16, &mut evidence);
        assert!(spans.is_empty());
        assert_eq!(causes(&evidence), [IncompleteCause::RulesetUnavailable]);
    }

    #[test]
    fn an_uncompilable_pattern_keeps_the_compilers_explanation() {
        // 001 built this detail and then overwrote it with `with_detail`, so the one situation where the
        // message matters reported only that a message existed.
        let r = rule("a.one", "(unclosed");
        let mut evidence = Evidence::new();
        let _ = set().matches(0, &r, b"anything", 16, &mut evidence);
        let detail = evidence.recorded_gaps()[0].detail().unwrap();
        assert!(detail.contains("a.one"), "must name the rule: {detail}");
        assert!(
            detail.len() > "rule `a.one` could not be compiled: ".len(),
            "must carry the compiler's reason, got {detail:?}"
        );
    }

    #[test]
    fn a_size_bomb_is_reported_at_match_time_if_it_reached_here() {
        let limits = RulesetLimits {
            max_compiled_bytes: 4096,
            ..RulesetLimits::default()
        };
        let s = PatternSet::new(1, limits);
        let r = rule("a.one", "a{1000}{1000}{1000}");
        let mut evidence = Evidence::new();
        let spans = s.matches(0, &r, b"aaaa", 16, &mut evidence);
        assert!(spans.is_empty());
        assert_eq!(causes(&evidence), [IncompleteCause::RulesetUnavailable]);
    }

    #[test]
    fn matching_works_across_invalid_utf8() {
        let r = rule("a.one", "needle");
        let prefix: &[u8] = b"\xff\xfe ";
        let mut haystack = prefix.to_vec();
        haystack.extend_from_slice(b"needle");
        haystack.push(0xff);
        let mut evidence = Evidence::new();
        let spans = set().matches(0, &r, &haystack, 16, &mut evidence);
        assert_eq!(spans.len(), 1);
        assert_eq!(
            spans[0].start,
            prefix.len(),
            "span is a byte offset into the original input, counting the malformed prefix"
        );
        assert_eq!(spans[0].end, prefix.len() + "needle".len());
    }
}
