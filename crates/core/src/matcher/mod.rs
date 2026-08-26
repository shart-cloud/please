//! The matcher — rules, the literal prefilter, and the compiled-pattern slots, behind one interface.
//!
//! # What this module is for is hiding a number
//!
//! 001 identified a rule by its **position** in the resolved rule slice, and that position was exchanged
//! across three seams:
//!
//! * [`prefilter::Prefilter::candidates`] returned candidate *indices*;
//! * the compiled-pattern store keyed slots by index;
//! * `Engine::scan` indexed back into the rule slice to read a rule's class, severity, and description.
//!
//! Three components agreeing on an ordering is a coupling that no type checks. Insert a rule, resolve an
//! override differently, or sort the slice by anything else, and every index means something else while
//! everything still compiles — and the failure would be a finding attributed to the wrong rule, which is
//! worse than no finding at all because it is believable.
//!
//! Positions are a fine way to key a cache and a terrible thing to put in an interface. So this module owns
//! the rule set, the prefilter, and the slots **together**, and what it hands out is a [`RuleMatch`] carrying
//! a reference to the rule itself. The index space still exists — it is how the slots are addressed, and it
//! is the right representation for that — but it is now unobservable from outside (FR-140, FR-141, SC-111).
//!
//! `tests/seams.rs` asserts this by reading the source: no `rules[` and no `.candidates(` outside this
//! directory, and no `usize` in any `pub fn` here.
//!
//! # Two compiled paths, one store
//!
//! Slots arrive pre-filled for caller-supplied rules and empty for built-in ones (FR-109, research P5).
//! Validation already paid to compile a caller's pattern in order to prove it safe, so throwing that away and
//! recompiling on first match would be paying twice for one guarantee; built-in patterns are proven in CI and
//! compiled lazily, so the eighty rules a given input does not mention stay out of the cold-start path. See
//! [`patterns::PatternSet::prefilled`].

mod patterns;
mod prefilter;

use crate::finalize::evidence::Evidence;
use crate::finalize::types::Span;
use crate::ruleset::{Rule, Ruleset, RulesetLimits};

use patterns::PatternSet;
use prefilter::Prefilter;
use regex::bytes::Regex;

/// One rule matching at one place.
///
/// Carries the **rule**, not its position. Everything a caller needs in order to build an observation — id,
/// class, severity, description — is reachable through the reference, so there is no reason for a position to
/// leave this module and no way for it to.
#[derive(Debug, Clone, Copy)]
pub struct RuleMatch<'a> {
    pub rule: &'a Rule,
    /// Where the match is, in the haystack that was searched. An **input** coordinate, which the caller
    /// already holds and can act on — unlike a rule position, which only this module can interpret.
    pub span: Span,
}

/// A rule set, its literal gate, and its compiled patterns.
#[derive(Debug)]
pub struct Matcher {
    ruleset: Ruleset,
    prefilter: Prefilter,
    patterns: PatternSet,
}

impl Matcher {
    /// Build from a validated rule set and whatever validation compiled on the way.
    pub fn build(ruleset: Ruleset, retained: Vec<Option<Regex>>, limits: RulesetLimits) -> Self {
        let prefilter = Prefilter::build(ruleset.all_rules());
        let patterns = PatternSet::prefilled(retained, limits);
        Self {
            ruleset,
            prefilter,
            patterns,
        }
    }

    pub fn ruleset(&self) -> &Ruleset {
        &self.ruleset
    }

    /// Whether a rule opts out of quoting suppression (FR-014).
    ///
    /// By id, because that is how rules are named. `Engine::scan` used to do this lookup itself over a slice
    /// the plan handed it; asking here means the rule slice has one holder rather than two.
    pub fn fires_in_quotes(&self, rule_id: &str) -> bool {
        self.ruleset
            .all_rules()
            .iter()
            .find(|rule| rule.id == rule_id)
            .is_some_and(|rule| rule.fires_in_quotes)
    }

    /// Does this rule only match at a frame boundary (005 FR-501)?
    ///
    /// Looked up by id, like [`Self::fires_in_quotes`], and false for an unknown rule for the same
    /// reason: an id the rule set does not know cannot have declared anything, and defaulting an unknown
    /// rule to *frame-anchored* would silently drop its findings.
    pub fn is_frame_anchored(&self, rule_id: &str) -> bool {
        self.ruleset
            .all_rules()
            .iter()
            .find(|rule| rule.id == rule_id)
            .is_some_and(|rule| rule.anchor == crate::Anchor::Frame)
    }

    /// Every match of every candidate rule against `haystack`.
    ///
    /// The literal prefilter runs first, in one linear pass, so text matching no literal — nearly all text —
    /// returns from here having compiled nothing. Saturation and uncompilable patterns record their own
    /// coverage gaps into `evidence` (FR-122), so there is no error for a caller to interpret.
    pub fn find<'a>(
        &'a self,
        haystack: &[u8],
        max_matches: u32,
        evidence: &mut Evidence,
    ) -> Vec<RuleMatch<'a>> {
        let rules = self.ruleset.all_rules();
        let mut found = Vec::new();
        for index in self.prefilter.candidates(haystack) {
            let rule = &rules[index];
            for span in self
                .patterns
                .matches(index, rule, haystack, max_matches, evidence)
            {
                found.push(RuleMatch { rule, span });
            }
        }
        found
    }

    /// Which rules match `haystack` at all, each reported once.
    ///
    /// The decoded path wants this rather than [`find`](Self::find): a payload repeated inside a decoded blob
    /// is still one concealed payload, and reporting each occurrence would let a single encoded region fill
    /// the reason budget. Expressed as its own operation rather than leaving the caller to de-duplicate,
    /// because de-duplicating by rule is a question about rules and this module owns those.
    pub fn matching_rules<'a>(
        &'a self,
        haystack: &[u8],
        max_matches: u32,
        evidence: &mut Evidence,
    ) -> Vec<&'a Rule> {
        // Still lazy, though [`FrameMap::build`] is now cheap — it is one `looks_like_json` probe rather
        // than the boundary map it used to be. This function is the decoded path's inner loop: it runs
        // once per decoded candidate, and a whole-input transform yields a copy of the entire document.
        // Not paying even a cheap probe on candidates that match nothing is free to keep.
        let mut frames: Option<crate::structure::FrameMap> = None;
        let rules = self.ruleset.all_rules();
        let mut found = Vec::new();
        for index in self.prefilter.candidates(haystack) {
            let rule = &rules[index];
            // A frame-anchored rule is anchored inside a decoded buffer too. The buffer is a document —
            // a whole-input fold is a copy of the ENTIRE document — and a rule declaring that its payload
            // only means something at the start of a unit cannot abandon that claim just because the text
            // arrived through a transform.
            //
            // Leaving it unanchored here is not a small omission. `docs/limits.md` records that a
            // whole-input transform is "a copy of the document that suppression does not cover"; making it
            // a copy the ANCHOR does not cover either turned three of this repository's own documents into
            // findings, through a leetspeak fold triggered by a hex digest.
            let spans = self
                .patterns
                .matches(index, rule, haystack, max_matches, evidence);
            if spans.is_empty() {
                continue;
            }
            if rule.anchor == crate::Anchor::Frame {
                let frames =
                    frames.get_or_insert_with(|| crate::structure::FrameMap::build(haystack));
                if !spans
                    .iter()
                    .any(|span| frames.is_frame(haystack, span.start))
                {
                    continue;
                }
            }
            found.push(rule);
        }
        found
    }

    /// Whether a rule's pattern has been compiled. Test and diagnostic use.
    ///
    /// Exposed because "was this compiled twice?" is the claim SC-106 makes and there is no way to observe it
    /// from outside otherwise. `false` for an unknown id, which is the honest answer: an absent rule has no
    /// compiled pattern.
    pub fn pattern_is_compiled(&self, rule_id: &str) -> bool {
        self.ruleset
            .all_rules()
            .iter()
            .position(|rule| rule.id == rule_id)
            .is_some_and(|index| self.patterns.is_compiled(index))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalize::types::DetectionClass;
    use crate::prepare;

    fn matcher() -> Matcher {
        let prepared = prepare::from_source(
            r#"
[ruleset]
name = "test.matcher"
version = "1.0.0"

[[rule]]
id = "override.ignore_previous"
class = "override"
severity = 85
literals = ["ignore"]
pattern = '(?i)\bignore\b'
description = "Test rule."

[[rule]]
id = "quiet.never_matches"
class = "boundary"
severity = 10
literals = ["zzzz"]
pattern = 'zzzz'
description = "Never fires."
"#,
            RulesetLimits::default(),
        )
        .expect("must prepare");
        let (ruleset, _, retained, limits) = prepared.into_parts();
        Matcher::build(ruleset, retained, limits)
    }

    #[test]
    fn a_match_carries_the_rule_rather_than_its_position() {
        let m = matcher();
        let mut evidence = Evidence::new();
        let found = m.find(b"please ignore that", 16, &mut evidence);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule.id, "override.ignore_previous");
        assert_eq!(found[0].rule.class, DetectionClass::Override);
        assert_eq!(found[0].rule.severity, 85);
        assert_eq!(found[0].span.start, 7);
    }

    #[test]
    fn text_matching_no_literal_finds_nothing_and_records_nothing() {
        // The prefilter's job, through the interface. Note what this does NOT assert: that nothing was
        // compiled. These rules are caller-supplied, so validation pre-filled their slots to prove them safe
        // — see `a_caller_supplied_pattern_arrives_already_compiled` below. The "compiles nothing" claim
        // belongs to BUILT-IN rules, whose slots arrive empty, and it is asserted in
        // `tests/preparation.rs::a_builtin_pattern_is_not_compiled_until_it_is_needed`.
        //
        // An earlier draft of this test asserted both here and contradicted the one below it.
        let m = matcher();
        let mut evidence = Evidence::new();
        assert!(m
            .find(b"an ordinary sentence about billing", 16, &mut evidence)
            .is_empty());
        assert!(m
            .matching_rules(b"an ordinary sentence about billing", 16, &mut evidence)
            .is_empty());
    }

    #[test]
    fn a_caller_supplied_pattern_arrives_already_compiled() {
        // FR-109. Validation compiled it to prove it safe; the slot was pre-filled from that work rather than
        // recompiled on first match.
        assert!(matcher().pattern_is_compiled("override.ignore_previous"));
    }

    #[test]
    fn matching_rules_reports_each_rule_once_however_often_it_matches() {
        let m = matcher();
        let mut evidence = Evidence::new();
        let rules = m.matching_rules(b"ignore ignore ignore ignore", 16, &mut evidence);
        assert_eq!(rules.len(), 1, "one rule, four matches");
        assert_eq!(rules[0].id, "override.ignore_previous");
    }

    #[test]
    fn fires_in_quotes_is_looked_up_by_id_and_is_false_for_an_unknown_rule() {
        let m = matcher();
        assert!(!m.fires_in_quotes("override.ignore_previous"));
        assert!(
            !m.fires_in_quotes("nonsense.rule"),
            "an absent rule does not opt out of anything"
        );
    }

    #[test]
    fn an_unknown_rule_has_no_compiled_pattern() {
        assert!(!matcher().pattern_is_compiled("nonsense.rule"));
    }
}
