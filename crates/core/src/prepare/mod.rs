//! Rule preparation — the only route from rule *text* to scanning capability (FR-101).
//!
//! This module exists to make one sentence true: **there is no way to obtain a scanning capability from
//! caller-supplied rules that have not been proven to compile within their resource budget.**
//!
//! Not "callers should validate first". Not "validation is recommended". No such path exists.
//!
//! # What was wrong
//!
//! 001 let a caller build an `Engine` from a `Ruleset` and *then* offered `Ruleset::validate_compiled` as a
//! separate courtesy, documented with "call this for any rule set you did not ship". Nothing in the tree
//! called it except a test. Safety was a property of call order, and the failure mode was silence: a caller
//! who never made the second call got a working scanner driven by rules nobody had proven could compile.
//!
//! A resource bomb in a rule file is a rule file that parses. `a{1000}{1000}{1000}` is nineteen bytes that
//! `regex_syntax` accepts in microseconds and that compiles to an automaton with on the order of 10⁹
//! states, so the cheap tier cannot see it and the expensive tier was the only thing that could — and it
//! was opt-in.
//!
//! # The surface
//!
//! Three ways in, and every one of them validates:
//!
//! | Entry | Provenance | Compiled validation | Cost |
//! |---|---|---|---|
//! | [`builtin`] | `Builtin`, minted here | not at run time — established in CI at default limits | ~4 ms |
//! | [`from_source`] | `Supplied` | **every rule, at construction** | proportional to the rules supplied |
//! | [`layered`] | per rule | **the caller's rules only** | proportional to the delta |
//!
//! What is deliberately **absent**: any operation that validates without producing a prepared rule set,
//! and any operation that produces one without validating. 001 shipped the first of those, and it was
//! never called.
//!
//! # The asymmetry is the design
//!
//! Built-in rules are proven in CI and compiled lazily, so cold start is unaffected by the eighty rules a
//! given input does not mention. Caller-supplied rules are proven at construction and arrive already
//! compiled, so the ~44 ms buys a warm scanner rather than being a toll. Each half pays where its guarantee
//! comes from, which is what keeps a ~25 ms cold-start budget while still proving untrusted rules safe.

pub mod prepared;
pub mod provenance;
pub mod validate;

pub use prepared::{PreparedRuleset, ValidationRecord};
pub use provenance::Provenance;

use crate::ruleset::{Ruleset, RulesetError, RulesetLimits};

/// The built-in rule set, embedded at compile time.
///
/// Embedded rather than read from disk so a first run needs no configuration, no filesystem, and no
/// network (FR-025, FR-031) — and so the same rule set works unchanged in a browser.
const BUILTIN_RULES: &str = include_str!("../../../../rules/builtin.toml");

/// The identity the built-in rule set must declare.
///
/// Checked rather than assumed, because [`builtin`] stamps `Provenance::Builtin` on whatever
/// [`BUILTIN_RULES`] contains and a mismatch here would mean the embedded file is not the file this code
/// thinks it is.
const BUILTIN_NAME: &str = "please.builtin";

/// The built-in rule set, prepared.
///
/// Compiles nothing: validity at default limits is established by a CI check (FR-106), and re-establishing
/// it per invocation would spend 1.8× the cold-start budget proving something already proven.
pub fn builtin() -> Result<PreparedRuleset, RulesetError> {
    builtin_with_limits(RulesetLimits::default())
}

/// The built-in rule set at caller-chosen limits.
///
/// Limits stricter than the defaults revalidate every rule, because the CI record was established at the
/// defaults and does not apply below them (FR-108). Rare path, and stating it is what stops "validated"
/// from being decoration.
pub fn builtin_with_limits(limits: RulesetLimits) -> Result<PreparedRuleset, RulesetError> {
    let ruleset = load_builtin(&limits)?;
    finish(ruleset, limits)
}

/// A caller-supplied rule set, replacing the built-in entirely.
///
/// **Every rule is validated**, including rules marked `enabled = false` (FR-107). Rejection is whole-set
/// and names the offending rule: a half-loaded rule set is indistinguishable from a deliberately weakened
/// one.
pub fn from_source(source: &str, limits: RulesetLimits) -> Result<PreparedRuleset, RulesetError> {
    let ruleset = Ruleset::from_toml_with_limits(source, &limits)?;
    finish(ruleset, limits)
}

/// The built-in set with caller additions and suppressions layered on top (FR-023).
///
/// Resolution order is fixed: base, then additions, then suppressions last — so a rule can be added by one
/// layer and switched off by another.
///
/// Validation is **delta only**: the caller's rules, not the union. The built-in half is already known
/// good, so validating it again would make adding one rule cost what validating eighty costs — the
/// difference between a `--rules` flag people use and one they pass once and never again (SC-105).
///
/// Suppression compiles nothing, because removing rules cannot introduce a resource problem (FR-110).
/// Suppressing an identifier that is not present is still an error: the usual cause is a typo, and a typo
/// that quietly leaves a rule enabled defeats the point of disabling it.
///
/// `base` of `None` means the built-in set. A `Some(base)` is caller-supplied and validated as such —
/// including when it names itself `please.builtin`, since provenance is not derived from content.
pub fn layered(
    base: Option<Ruleset>,
    additions: Vec<Ruleset>,
    suppress: &[String],
    limits: RulesetLimits,
) -> Result<PreparedRuleset, RulesetError> {
    let base = match base {
        Some(supplied) => supplied,
        None => load_builtin(&limits)?,
    };
    let resolved = Ruleset::resolve(base, additions, suppress, &limits)?;
    finish(resolved, limits)
}

/// Establish that the embedded rule set compiles within default limits (FR-106).
///
/// **The check the built-in fast path rests on, and which did not exist in 001** — there, the expensive
/// tier was never invoked by anything, on any rule set, including the embedded one. `builtin` skips
/// compiled validation on the strength of this, so without it the fast path's safety rests on nothing.
///
/// Public because it is run as its own CI step rather than only as a side effect of the test suite
/// passing (T043). A guarantee established by a named check is one you can point at.
pub fn validate_builtin_at_default_limits() -> Result<(), RulesetError> {
    let limits = RulesetLimits::default();
    let ruleset = Ruleset::from_toml_with_limits(BUILTIN_RULES, &limits)?;
    for rule in ruleset.all_rules() {
        validate::compile_within(&rule.id, &rule.pattern, &limits)?;
    }
    Ok(())
}

/// Parse the embedded rule set and stamp its rules `Builtin`.
///
/// The stamping is here and nowhere else. `ruleset::validate` marks everything it parses `Supplied`,
/// including these bytes, and this function upgrades them afterwards — which it can do only because
/// `Provenance::builtin` is `pub(super)` to this module tree (FR-104).
///
/// Upgrading rather than passing an origin down into parsing is deliberate: it means there is exactly one
/// expression of `Provenance::builtin()` in the crate, and a new loading path cannot accidentally acquire
/// the trusted stamp by threading an argument through.
fn load_builtin(limits: &RulesetLimits) -> Result<Ruleset, RulesetError> {
    let mut ruleset = Ruleset::from_toml_with_limits(BUILTIN_RULES, limits)?;
    debug_assert_eq!(
        ruleset.id().name,
        BUILTIN_NAME,
        "the embedded rule set must be the one this code thinks it is",
    );
    ruleset.stamp_provenance(Provenance::builtin());
    Ok(ruleset)
}

/// Validate a resolved rule set and wrap it. The single funnel every entry point goes through.
///
/// One function so there is one answer to "does this validate?", rather than three constructors that each
/// have to remember to. `finish` is not public and does not need to be: reaching it requires having gone
/// through one of the three entry points above.
fn finish(ruleset: Ruleset, limits: RulesetLimits) -> Result<PreparedRuleset, RulesetError> {
    // Whether the CI record applies is a question about limits, not about rules (FR-108). The record was
    // established at the defaults, so it applies exactly while the limits in force are no stricter.
    let builtin_is_covered = limits.permits_at_least(&RulesetLimits::default());

    let compiled = validate::validate_resolved(ruleset.all_rules(), &limits, builtin_is_covered)?;
    let covered_by_ci = ruleset.all_rules().len() - compiled.compiled_here;

    let record = ValidationRecord::new(limits, compiled.compiled_here, covered_by_ci);
    Ok(PreparedRuleset::new(ruleset, record, compiled.slots))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_rule_set_is_stamped_builtin() {
        let prepared = builtin().expect("the embedded rule set must prepare");
        assert!(
            prepared.rules().iter().all(|r| r.provenance.is_builtin()),
            "every embedded rule must carry builtin provenance, or the delta validates the wrong half"
        );
    }

    #[test]
    fn the_same_source_supplied_by_a_caller_is_not_stamped_builtin() {
        // The property FR-104 turns on. Identical bytes, different route in, different trust.
        let prepared = from_source(BUILTIN_RULES, RulesetLimits::default()).expect("must prepare");
        assert!(
            prepared.rules().iter().all(|r| !r.provenance.is_builtin()),
            "rules a caller handed us are caller-supplied whatever the file says"
        );
        assert_eq!(
            prepared.record().compiled_here(),
            prepared.rules().len(),
            "a caller-supplied set is validated in full, however familiar it looks"
        );
    }

    #[test]
    fn the_builtin_path_compiles_nothing_at_default_limits() {
        let prepared = builtin().expect("must prepare");
        assert_eq!(prepared.record().compiled_here(), 0);
        assert_eq!(prepared.record().covered_by_ci(), prepared.rules().len());
    }

    #[test]
    fn a_record_covers_looser_limits_and_not_tighter_ones() {
        let prepared = builtin().expect("must prepare");
        assert!(prepared.record().covers(&RulesetLimits::default()));
        assert!(
            prepared.record().covers(&RulesetLimits {
                max_compiled_bytes: 4 * 1024 * 1024,
                ..RulesetLimits::default()
            }),
            "relaxing a budget cannot invalidate a proof made under a smaller one"
        );
        assert!(
            !prepared.record().covers(&RulesetLimits {
                max_compiled_bytes: 512,
                ..RulesetLimits::default()
            }),
            "a proof at 1 MiB says nothing about whether these patterns fit 512 bytes"
        );
    }
}
