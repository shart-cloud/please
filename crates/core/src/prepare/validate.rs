//! Resource validation, and the delta that keeps it affordable.
//!
//! Moved here from `ruleset::validate` (T038). The cheap tier still runs inside rule-set loading, because
//! it establishes *legality* and a rule set that is not legal should not parse. What moved is the
//! **expensive** tier, because it establishes *safety*, and safety is preparation's job — leaving it in
//! `ruleset` is what allowed it to be an optional call in the first place.
//!
//! # Two tiers, measured
//!
//! On 80 representative rules (research D17):
//!
//! | Check | Cost | Catches |
//! |---|---|---|
//! | Syntax parse | ~3.9 ms | look-around, backreferences, malformed patterns |
//! | Full compile | ~44 ms | the above, plus counted-repetition size bombs |
//!
//! 44 ms is 1.8× the entire cold-start budget for a process a hook launches once per tool call. That
//! number is why the expensive tier is not simply run on everything always, and it is the whole reason the
//! delta below exists rather than being an optimisation someone thought was clever.
//!
//! # The delta
//!
//! Validate the rules the caller supplied. Skip built-in rules whose validity is already established by
//! the CI check, unless the limits in force are stricter than the ones that check ran at.
//!
//! Without this, `--rules extra.toml` adding one rule would cost what validating eighty costs, and the
//! difference between that and a proportional cost is the difference between a flag people use and a flag
//! people pass once and never again (SC-105).
//!
//! # Retention
//!
//! Proving a pattern safe compiles it. 001 compiled it, measured the program size, and dropped the
//! `Regex` on the floor — then compiled it again, lazily, the first time an input hit its literal gate.
//! [`compile_within`] returns the compiled form so the second compile never happens (FR-109, SC-106).

use regex::bytes::{Regex, RegexBuilder};

use crate::ruleset::{Rule, RulesetError, RulesetLimits};

/// Compile one pattern under a size limit and **keep** the result.
///
/// This is where the counted-repetition expansion case is caught: `a{1000}{1000}{1000}` is nineteen bytes
/// of source that `regex_syntax::parse` accepts in microseconds and that compiles to an automaton with on
/// the order of 10⁹ states. Without a compiled-size limit, a rule set copied from an untrusted source is a
/// memory-exhaustion path into the tool meant to prevent that class of thing.
pub fn compile_within(
    id: &str,
    pattern: &str,
    limits: &RulesetLimits,
) -> Result<Regex, RulesetError> {
    match RegexBuilder::new(pattern)
        .size_limit(limits.max_compiled_bytes)
        .build()
    {
        Ok(regex) => Ok(regex),
        Err(regex::Error::CompiledTooBig(_)) => Err(RulesetError::PatternTooComplex {
            rule: id.to_string(),
            limit: limits.max_compiled_bytes,
        }),
        Err(e) => Err(RulesetError::PatternInvalid {
            rule: id.to_string(),
            detail: e.to_string(),
        }),
    }
}

/// What validating a resolved set produced: one slot per rule, in rule order.
///
/// `None` means the rule was not compiled here — it is a built-in rule covered by the CI record. The
/// matcher fills those lazily on first literal hit, which is what keeps cold start unaffected by the
/// eighty rules nobody's input mentions.
///
/// Index-aligned with the rule slice deliberately, and this is the one place in the crate where a rule
/// position is load-bearing. It never leaves preparation: the slots are handed to the matcher, which owns
/// the position space privately (FR-140). Phase 7 makes that structural.
pub(super) struct Compiled {
    pub slots: Vec<Option<Regex>>,
    /// How many patterns were actually compiled. The observable form of "cost proportional to the
    /// caller's rules", which is what SC-105 asserts and what the bench measures.
    pub compiled_here: usize,
}

/// Validate every rule that needs it, retaining what was compiled (FR-102, FR-107, SC-105).
///
/// Covers **every rule present**, including rules marked `enabled = false`. Skipping disabled rules looks
/// like an obvious saving and is a hole: `enabled` is a field in a file, so flipping it to `true` would
/// turn a validated rule set into an unvalidated one *with no construction occurring*, and the validation
/// state would go stale in silence (FR-107).
///
/// `builtin_is_covered` decides whether the CI record applies. The caller computes it from the limits in
/// force, because that is a question about limits rather than about any individual rule (FR-108).
pub(super) fn validate_resolved(
    rules: &[Rule],
    limits: &RulesetLimits,
    builtin_is_covered: bool,
) -> Result<Compiled, RulesetError> {
    let mut slots: Vec<Option<Regex>> = Vec::with_capacity(rules.len());
    let mut compiled_here = 0;

    for rule in rules {
        if builtin_is_covered && rule.provenance.is_builtin() {
            slots.push(None);
            continue;
        }
        slots.push(Some(compile_within(&rule.id, &rule.pattern, limits)?));
        compiled_here += 1;
    }

    Ok(Compiled {
        slots,
        compiled_here,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::finalize::types::DetectionClass;
    use crate::prepare::Provenance;

    fn rule(id: &str, pattern: &str, provenance: Provenance) -> Rule {
        Rule {
            id: id.to_string(),
            class: DetectionClass::Override,
            severity: 50,
            literals: vec!["x".to_string()],
            pattern: pattern.to_string(),
            fires_in_quotes: false,
            enabled: true,
            description: "test".to_string(),
            provenance,
        }
    }

    #[test]
    fn a_counted_repetition_bomb_exceeds_the_size_limit() {
        let limits = RulesetLimits {
            max_compiled_bytes: 4096,
            ..RulesetLimits::default()
        };
        let err = compile_within("t.t", "a{100}{100}{100}", &limits).unwrap_err();
        assert!(
            matches!(err, RulesetError::PatternTooComplex { .. }),
            "expected PatternTooComplex, got {err:?}"
        );
    }

    #[test]
    fn a_validated_pattern_is_returned_rather_than_discarded() {
        // FR-109 in one assertion. 001 returned `Result<(), _>` here, which is the same check and half
        // the value.
        let regex = compile_within("t.t", "needle", &RulesetLimits::default()).unwrap();
        assert!(regex.is_match(b"a needle here"));
    }

    #[test]
    fn the_delta_compiles_only_the_caller_supplied_rules() {
        let rules = [
            rule("theirs.one", "needle", Provenance::builtin()),
            rule("mine.one", "haystack", Provenance::supplied()),
            rule("theirs.two", "other", Provenance::builtin()),
        ];
        let got = validate_resolved(&rules, &RulesetLimits::default(), true).unwrap();

        assert_eq!(got.compiled_here, 1, "only the caller's rule needs proving");
        assert!(got.slots[0].is_none());
        assert!(got.slots[1].is_some(), "the caller's rule must be retained");
        assert!(got.slots[2].is_none());
    }

    #[test]
    fn a_stale_record_forces_every_rule_to_be_compiled() {
        // `builtin_is_covered: false` is what a caller tightening limits below default produces.
        let rules = [
            rule("theirs.one", "needle", Provenance::builtin()),
            rule("mine.one", "haystack", Provenance::supplied()),
        ];
        let got = validate_resolved(&rules, &RulesetLimits::default(), false).unwrap();
        assert_eq!(got.compiled_here, 2);
        assert!(got.slots.iter().all(Option::is_some));
    }

    #[test]
    fn a_disabled_rule_is_validated_anyway() {
        // FR-107. It will never match; `enabled` is still flippable data.
        let mut disabled = rule("mine.off", "a{100}{100}{100}", Provenance::supplied());
        disabled.enabled = false;
        let limits = RulesetLimits {
            max_compiled_bytes: 4096,
            ..RulesetLimits::default()
        };
        assert!(validate_resolved(&[disabled], &limits, true).is_err());
    }

    #[test]
    fn a_builtin_bomb_is_caught_when_the_record_does_not_cover_it() {
        // The reason `builtin_is_covered` is a parameter rather than read off the rule: trust in a
        // built-in rule is trust in a CI check at stated limits, not trust in the rule.
        let bomb = rule("theirs.bomb", "a{100}{100}{100}", Provenance::builtin());
        let limits = RulesetLimits {
            max_compiled_bytes: 4096,
            ..RulesetLimits::default()
        };
        assert!(validate_resolved(std::slice::from_ref(&bomb), &limits, true).is_ok());
        assert!(validate_resolved(&[bomb], &limits, false).is_err());
    }
}
