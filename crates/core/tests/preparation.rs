//! Rule preparation: the one sentence this feature exists to make true.
//!
//! **There is no way to obtain a scanning capability from caller-supplied rules that have not been proven
//! to compile within their resource budget.**
//!
//! Not "callers should validate first". Not "validation is recommended". No such path exists.
//!
//! # What was wrong
//!
//! 001 shipped `Ruleset::validate_compiled` as a separate, public, optional call — with a doc comment
//! saying "call this for any rule set you did not ship" — and nothing in the tree called it except a
//! test. Safety was therefore a property of *call order*, and the failure mode was silence: a caller who
//! never made the second call got a working `Engine` driven by rules nobody had proven could compile. The
//! comment in `ruleset_load.rs` even asserted "which is exactly what the CLI does for `--rules`", and the
//! CLI has no `--rules` flag.
//!
//! A safety step a caller can omit is a safety step some caller has omitted.
//!
//! # How these tests are organised
//!
//! `every_public_construction_path_rejects_a_resource_bomb` is the important one, and it is deliberately
//! written as an *enumeration* rather than as several tests. A new constructor added later is a new way in,
//! and a per-path test suite silently fails to cover it. The enumeration is a list a reviewer can compare
//! against the public surface.

mod support;

use please_core::prepare::{self, Provenance};
use please_core::ruleset::{Ruleset, RulesetError, RulesetLimits};
use please_core::Engine;

/// One way into a scanning capability, as a callable.
///
/// Boxed rather than a plain `fn` because each attempt closes over the bomb's source text, and named
/// rather than written inline because the inline spelling is unreadable — which matters here more than
/// usual, since this list *is* the assertion.
type ConstructionPath = Box<dyn Fn() -> Result<(), RulesetError>>;

/// The rule set from `tests/fixtures/rules/bomb.toml`: parses cleanly, must never produce a scanner.
fn bomb() -> String {
    std::fs::read_to_string(support::fixtures().join("rules/bomb.toml"))
        .expect("tests/fixtures/rules/bomb.toml must exist (T025)")
}

/// A legitimate caller-supplied rule set, to prove the gate is a gate and not a wall.
fn legitimate() -> &'static str {
    r#"
[ruleset]
name = "acme.internal"
version = "1.0.0"

[[rule]]
id = "acme.tool_marker"
class = "boundary"
severity = 70
literals = ["ACME-TOOL"]
pattern = '(?i)ACME-TOOL:\s*\w+'
description = "Forged internal tool marker."
"#
}

/// Limits tight enough that the bomb is over budget but ordinary rules are not.
fn limits() -> RulesetLimits {
    RulesetLimits {
        max_compiled_bytes: 64 * 1024,
        ..RulesetLimits::default()
    }
}

// ── SC-101, SC-102: no route in ────────────────────────────────────────────────────────────────

#[test]
fn every_public_construction_path_rejects_a_resource_bomb() {
    // The enumeration. Each entry is one way to get a scanning capability out of caller-supplied text,
    // and every one must refuse. Compare this list against the public surface when adding a constructor:
    // an entry missing here is a path nobody is testing.
    let source = bomb();

    let attempts: Vec<(&str, ConstructionPath)> = vec![
        (
            "prepare::from_source",
            Box::new({
                let s = source.clone();
                move || prepare::from_source(&s, RulesetLimits::default()).map(|_| ())
            }),
        ),
        (
            "prepare::from_source, tightened limits",
            Box::new({
                let s = source.clone();
                move || prepare::from_source(&s, limits()).map(|_| ())
            }),
        ),
        (
            "prepare::layered, as an addition to the built-in set",
            Box::new({
                let s = source.clone();
                move || {
                    let addition = Ruleset::from_toml(&s)?;
                    prepare::layered(None, vec![addition], &[], RulesetLimits::default())
                        .map(|_| ())
                }
            }),
        ),
        (
            "prepare::layered, replacing the built-in base",
            Box::new({
                let s = source.clone();
                move || {
                    let base = Ruleset::from_toml(&s)?;
                    prepare::layered(Some(base), Vec::new(), &[], RulesetLimits::default())
                        .map(|_| ())
                }
            }),
        ),
        (
            "Engine::from_toml",
            Box::new({
                let s = source.clone();
                move || Engine::from_toml(&s).map(|_| ())
            }),
        ),
        (
            "Engine::builder().base(..)",
            Box::new({
                let s = source.clone();
                move || {
                    let base = Ruleset::from_toml(&s)?;
                    Engine::builder().base(base).build().map(|_| ())
                }
            }),
        ),
        (
            "Engine::builder().add_ruleset(..)",
            Box::new({
                let s = source.clone();
                move || {
                    let addition = Ruleset::from_toml(&s)?;
                    Engine::builder().add_ruleset(addition).build().map(|_| ())
                }
            }),
        ),
    ];

    let mut accepted: Vec<&str> = Vec::new();
    for (name, attempt) in &attempts {
        match attempt() {
            Ok(()) => accepted.push(name),
            Err(RulesetError::PatternTooComplex { rule, .. }) => {
                assert!(
                    rule.starts_with("bomb."),
                    "{name}: rejected the wrong rule (`{rule}`)"
                );
            }
            Err(other) => panic!(
                "{name}: rejected for the wrong reason. A size bomb must be \
                 PatternTooComplex — anything else means the bomb was caught by accident \
                 and a different bomb would get through. Got {other:?}"
            ),
        }
    }

    assert!(
        accepted.is_empty(),
        "these construction paths accepted a resource bomb: {accepted:?}"
    );
}

#[test]
fn every_public_construction_path_accepts_a_legitimate_rule_set() {
    // The other half, and not a formality: a gate that rejects everything would pass the test above.
    prepare::from_source(legitimate(), RulesetLimits::default())
        .expect("prepare::from_source must accept a legitimate rule set");

    let addition = Ruleset::from_toml(legitimate()).expect("must parse");
    prepare::layered(None, vec![addition], &[], RulesetLimits::default())
        .expect("prepare::layered must accept a legitimate addition");

    Engine::from_toml(legitimate()).expect("Engine::from_toml must accept a legitimate rule set");

    let addition = Ruleset::from_toml(legitimate()).expect("must parse");
    Engine::builder()
        .add_ruleset(addition)
        .build()
        .expect("the builder must accept a legitimate addition");
}

#[test]
fn rejection_names_the_offending_rule() {
    // A diagnostic that says "invalid rule set" without saying which rule costs someone an afternoon.
    let err = prepare::from_source(&bomb(), limits()).unwrap_err();
    let message = err.to_string();
    assert!(
        message.contains("bomb."),
        "the diagnostic must name the rule, got: {message}"
    );
}

// ── FR-107: disabled rules are validated too ───────────────────────────────────────────────────

#[test]
fn a_rule_set_whose_only_defective_rule_is_disabled_is_still_rejected() {
    // This looks like waste — a disabled rule will never match, so why prove it compiles? Because
    // `enabled` is a field in a file. Skipping it would mean flipping `enabled = true` turns a validated
    // rule set into an unvalidated one WITH NO CONSTRUCTION OCCURRING, and the validation state goes
    // stale in silence. Validating everything present keeps the guarantee true across later edits.
    let source = r#"
[ruleset]
name = "test.disabled_bomb"
version = "1.0.0"

[[rule]]
id = "quiet.bomb"
class = "override"
severity = 90
literals = ["boom"]
pattern = 'a{1000}{1000}{1000}'
enabled = false
description = "A bomb that is switched off. Still a bomb."
"#;

    let err = prepare::from_source(source, limits()).unwrap_err();
    assert!(
        matches!(err, RulesetError::PatternTooComplex { .. }),
        "a disabled rule must still be validated (FR-107), got {err:?}"
    );
}

// ── FR-106: the built-in set's validity is established, not assumed ────────────────────────────

#[test]
fn the_builtin_rule_set_passes_compiled_validation_at_default_limits() {
    // **The check FR-106 requires and that has never existed.**
    //
    // Everything about the built-in fast path rests on this one fact: preparation skips compiled
    // validation for built-in rules at default limits, on the grounds that CI has already established it.
    // In 001 nothing established it — the expensive tier was never invoked by anything, on any rule set,
    // including the embedded one. The fast path's safety rested on nothing at all.
    //
    // This is the cheapest test in the feature and the one that makes the rest coherent. It is also run
    // as its own CI step (T043), so the guarantee is established by a named check rather than as a
    // side effect of the suite passing.
    prepare::validate_builtin_at_default_limits().expect(
        "the embedded rule set must compile within default limits. If this fails, the built-in \
         fast path is unsound and every `Engine::builtin()` is unvalidated",
    );
}

// ── FR-108: a record is only good for the limits it names ──────────────────────────────────────

#[test]
fn limits_stricter_than_the_record_force_revalidation() {
    // "Validated" is meaningless without stating against what. If a record at generous limits satisfied
    // construction at severe ones, a caller could validate at 1 MiB and run at 4 KiB and the record would
    // still claim coverage.
    //
    // The built-in set's CI record is at DEFAULT limits, so a caller tightening them below default gets
    // every built-in rule revalidated rather than waved through.
    let generous = prepare::builtin().expect("the built-in set must prepare");
    assert_eq!(
        generous.record().compiled_here(),
        0,
        "at default limits the built-in set is covered by CI and must compile nothing"
    );

    let tightened = prepare::builtin_with_limits(RulesetLimits {
        max_compiled_bytes: 512 * 1024,
        ..RulesetLimits::default()
    })
    .expect("the built-in set must still validate at half the default compiled budget");
    assert!(
        tightened.record().compiled_here() > 0,
        "tightened limits must revalidate the built-in set, not reuse the CI record"
    );
}

#[test]
fn limits_more_generous_than_the_record_reuse_it() {
    // The converse, which is what keeps the fast path fast. A record at default limits covers any
    // construction whose limits are no stricter, because a pattern that fits a small budget fits a
    // larger one.
    let relaxed = prepare::builtin_with_limits(RulesetLimits {
        max_compiled_bytes: 4 * 1024 * 1024,
        ..RulesetLimits::default()
    })
    .expect("relaxing a limit cannot invalidate anything");
    assert_eq!(relaxed.record().compiled_here(), 0);
}

// ── FR-109, SC-106: the work of proving a rule safe is not thrown away ─────────────────────────

#[test]
fn a_caller_supplied_pattern_is_compiled_exactly_once() {
    // Proving a pattern safe compiles it. 001 compiled it, checked the size, and dropped the result on
    // the floor — then compiled it a second time, lazily, on the first input that hit its literal gate.
    // Twice the cost for one guarantee.
    //
    // Retention is what makes the ~44 ms honest: it is the price of a scanner that is already warm, not a
    // toll paid before the real work starts.
    let prepared =
        prepare::from_source(legitimate(), RulesetLimits::default()).expect("must prepare");
    assert_eq!(
        prepared.record().compiled_here(),
        1,
        "the one caller-supplied rule must be compiled during validation"
    );

    let engine = Engine::prepared(prepared);
    assert!(
        engine.pattern_is_compiled("acme.tool_marker"),
        "validation compiled this pattern; the engine must reuse it rather than compile it again"
    );
}

#[test]
fn validation_cost_is_proportional_to_the_caller_s_rules_not_the_resolved_set() {
    // SC-105, as a count rather than a duration. Timing assertions are flaky on shared runners; the count
    // is what the design constrains, and `benches/preparation.rs` measures the consequence.
    //
    // If this ever equalled the resolved size, `--rules one-extra.toml` would cost what validating
    // eighty-one rules costs, and the flag would be one people pass once and never again.
    let builtin_count = prepare::builtin().expect("must prepare").rules().len();
    assert!(
        builtin_count > 4,
        "this test is only meaningful while the built-in set is larger than the additions ({builtin_count})"
    );

    for extra in [1usize, 2, 4] {
        let mut source = String::from("[ruleset]\nname = \"acme.many\"\nversion = \"1.0.0\"\n");
        for i in 0..extra {
            source.push_str(&format!(
                "\n[[rule]]\nid = \"acme.rule_{i}\"\nclass = \"override\"\nseverity = 50\n\
                 literals = [\"marker{i}\"]\npattern = '(?i)\\bmarker{i}\\b'\n\
                 description = \"Bench rule {i}.\"\n"
            ));
        }

        let addition = Ruleset::from_toml(&source).expect("must parse");
        let prepared = prepare::layered(None, vec![addition], &[], RulesetLimits::default())
            .expect("must prepare");

        assert_eq!(
            prepared.record().compiled_here(),
            extra,
            "layering {extra} rule(s) onto {builtin_count} must compile {extra}, not {}",
            builtin_count + extra
        );
        assert_eq!(
            prepared.record().covered_by_ci(),
            builtin_count,
            "the built-in half must be covered by the CI record, not revalidated"
        );
    }
}

#[test]
fn a_builtin_pattern_is_not_compiled_until_it_is_needed() {
    // The asymmetry is the design, not an inconsistency. Built-in rules are proven in CI, so preparation
    // compiles none of them and the ~25 ms cold start is unaffected; a caller's rules are proven at
    // construction, so they arrive already compiled. Each pays where its guarantee comes from.
    let engine = Engine::builtin().expect("must prepare");
    assert!(
        !engine.pattern_is_compiled("override.disregard_prior"),
        "a built-in pattern must stay lazy — compiling all of them is the 44 ms cold start the \
         two-tier design exists to avoid"
    );
}

// ── FR-110: suppression needs no compiled validation ───────────────────────────────────────────

#[test]
fn suppression_alone_compiles_nothing_and_still_rejects_an_unknown_id() {
    // Removing rules cannot introduce a resource problem, so suppressing costs nothing. Suppressing an
    // identifier that is not there is still an error, because the usual cause is a typo and a typo that
    // quietly leaves a rule enabled defeats the point of disabling it.
    let prepared = prepare::layered(
        None,
        Vec::new(),
        &["override.disregard_prior".to_string()],
        RulesetLimits::default(),
    )
    .expect("suppressing a built-in rule must succeed");
    assert_eq!(prepared.record().compiled_here(), 0);

    let err = prepare::layered(
        None,
        Vec::new(),
        &["nonsense.rule".to_string()],
        RulesetLimits::default(),
    )
    .unwrap_err();
    assert!(matches!(err, RulesetError::UnknownSuppression { .. }));
}

// ── FR-105: provenance survives resolution, per rule ───────────────────────────────────────────

#[test]
fn provenance_survives_resolution_at_the_granularity_of_a_rule() {
    // This is what makes delta validation possible at all: after resolution you must still be able to
    // tell which half of the set is untrusted. A per-SET flag would collapse the layered case into
    // "contains caller rules", and then adding one rule would cost what validating eighty costs.
    let addition = Ruleset::from_toml(legitimate()).expect("must parse");
    let prepared = prepare::layered(None, vec![addition], &[], RulesetLimits::default())
        .expect("must prepare");

    let mine = prepared
        .rules()
        .iter()
        .find(|r| r.id == "acme.tool_marker")
        .expect("the addition must survive resolution");
    assert_eq!(mine.provenance, Provenance::supplied());

    let theirs = prepared
        .rules()
        .iter()
        .find(|r| r.id == "override.disregard_prior")
        .expect("the built-in rules must survive resolution");
    assert!(
        theirs.provenance.is_builtin(),
        "a built-in rule must keep its provenance through resolution"
    );
}

#[test]
fn a_caller_replacing_a_builtin_rule_owns_the_replacement() {
    // The displaced rule leaves the set, so what remains under that id is caller-supplied and must be
    // validated as such. Otherwise overriding a built-in id would be a way to inherit its trust.
    let source = r#"
[ruleset]
name = "acme.override"
version = "1.0.0"

[[rule]]
id = "override.disregard_prior"
class = "override"
severity = 10
literals = ["ignore"]
pattern = '(?i)\bignore\b'
description = "A caller's replacement for a built-in rule."
"#;
    let addition = Ruleset::from_toml(source).expect("must parse");
    let prepared = prepare::layered(None, vec![addition], &[], RulesetLimits::default())
        .expect("must prepare");

    let replaced = prepared
        .rules()
        .iter()
        .find(|r| r.id == "override.disregard_prior")
        .expect("the id must still be present");
    assert_eq!(
        replaced.provenance,
        Provenance::supplied(),
        "replacing a built-in rule must not inherit its provenance"
    );
    assert_eq!(
        replaced.severity, 10,
        "the caller's rule is the one that survived"
    );
    assert_eq!(
        prepared.record().compiled_here(),
        1,
        "the replacement is caller-supplied and must be validated"
    );
}

#[test]
fn naming_a_rule_set_after_the_builtin_earns_nothing() {
    // FR-104 from the outside. Provenance is not derived from content, and a name is content.
    let source = bomb().replace(r#"name = "test.bomb""#, r#"name = "please.builtin""#);
    let err = prepare::from_source(&source, limits()).unwrap_err();
    assert!(
        matches!(err, RulesetError::PatternTooComplex { .. }),
        "calling yourself the built-in set must buy nothing, got {err:?}"
    );
}

// ── FR-111: identity covers trust ──────────────────────────────────────────────────────────────

#[test]
fn two_rule_sets_differing_only_in_trust_origin_are_distinguishable() {
    // A verdict records the rule-set identity that produced it. If identity covered content alone, an
    // auditor reading an old verdict could not tell whether caller rules were involved — which is
    // precisely the question worth asking about a finding somebody disputes.
    let builtin = prepare::builtin().expect("must prepare");

    let same_content = prepare::from_source(
        &std::fs::read_to_string(support::repo_root().join("rules/builtin.toml"))
            .expect("the embedded rule set must also exist on disk"),
        RulesetLimits::default(),
    )
    .expect("the built-in source must prepare as a caller-supplied set too");

    assert_eq!(
        builtin.ruleset().id().digest,
        same_content.ruleset().id().digest,
        "the CONTENT digest must be identical — same rules, same bytes"
    );
    assert_ne!(
        builtin.id().digest,
        same_content.id().digest,
        "the PREPARED digest must differ: identical rules, different trust origin (FR-111)"
    );
}

#[test]
fn identity_is_stable_across_preparations() {
    // Attribution is worthless if it drifts. Two preparations of the same source must agree, or a stored
    // verdict cannot be matched to the rules that produced it (SC-012).
    let one = prepare::builtin().expect("must prepare");
    let two = prepare::builtin().expect("must prepare");
    assert_eq!(one.id().digest, two.id().digest);
}
