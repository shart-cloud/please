//! Rule-set loading, rejection, and resolution.
//!
//! A rule set is **caller-supplied**, which makes it an input to the scanner rather than part of it
//! (FR-023). So these tests are not about tidiness — they are the same class of test as the invariant
//! tests: a rule set copied from a third party must not be able to hurt the host, and a typo must not
//! be able to silently switch off a detection.
//!
//! Two rejections are load-bearing and easy to overlook:
//!
//! * **Unknown fields are rejected, not ignored.** `severty = 90` in a permissive loader is a rule
//!   running at whatever the default severity is, forever, silently.
//! * **Resource limits are enforced.** `a{5}{5}{5}{5}{5}{5}` is twenty bytes of source and an enormous
//!   automaton. Without a compiled-size limit, a shared rule set is a memory-exhaustion path.

use please_core::ruleset::{Ruleset, RulesetError, RulesetLimits};

fn header() -> &'static str {
    r#"
[ruleset]
name = "test.fixture"
version = "1.0.0"
"#
}

fn with_rule(body: &str) -> String {
    format!("{}\n[[rule]]\n{}", header(), body)
}

fn valid_rule() -> &'static str {
    r#"
id = "override.ignore_previous"
class = "override"
severity = 85
literals = ["ignore"]
pattern = '(?i)\bignore\b'
description = "Instruction to disregard prior instructions."
"#
}

// ── Acceptance ─────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_well_formed_rule_set_loads() {
    let set = Ruleset::from_toml(&with_rule(valid_rule())).expect("should load");
    assert_eq!(set.id().name, "test.fixture");
    assert_eq!(set.id().version, "1.0.0");
    assert_eq!(set.len(), 1);
    assert_eq!(set.id().digest.len(), 16);
}

#[test]
fn a_rule_set_with_no_rules_loads() {
    // Legal and useful: a caller can ship a set that only retunes bands.
    let set = Ruleset::from_toml(header()).expect("should load");
    assert!(set.is_empty());
}

#[test]
fn optional_fields_take_their_documented_defaults() {
    let set = Ruleset::from_toml(&with_rule(valid_rule())).unwrap();
    let rule = &set.all_rules()[0];
    assert!(!rule.fires_in_quotes, "fires_in_quotes defaults to false");
    assert!(rule.enabled, "enabled defaults to true");
}

#[test]
fn bands_default_when_absent_and_override_when_present() {
    let set = Ruleset::from_toml(header()).unwrap();
    assert_eq!(set.bands().high, 70);

    let custom = format!("{}\n[bands]\nhigh = 55\n", header());
    let set = Ruleset::from_toml(&custom).unwrap();
    assert_eq!(set.bands().high, 55);
    assert_eq!(set.bands().low, 20, "unspecified bands keep their defaults");
}

// ── Shape rejections ───────────────────────────────────────────────────────────────────────────

#[test]
fn invalid_toml_is_rejected() {
    let err = Ruleset::from_toml("this is not = = toml").unwrap_err();
    assert!(matches!(err, RulesetError::Toml { .. }), "got {err:?}");
}

#[test]
fn a_missing_ruleset_header_is_rejected() {
    let err = Ruleset::from_toml("[bands]\nlow = 10\n").unwrap_err();
    assert!(
        matches!(&err, RulesetError::MissingField { field, .. } if field == "ruleset"),
        "got {err:?}"
    );
}

#[test]
fn unknown_fields_are_rejected_not_ignored() {
    // The failure mode this prevents: `severty = 90` in a permissive loader is a rule silently running
    // at the default severity forever, and nobody finds out.
    let body = valid_rule().replace("severity = 85", "severity = 85\nseverty = 90");
    let err = Ruleset::from_toml(&with_rule(&body)).unwrap_err();
    match err {
        RulesetError::UnknownField { rule, field } => {
            assert_eq!(field, "severty");
            assert_eq!(
                rule.as_deref(),
                Some("override.ignore_previous"),
                "the diagnostic must name the rule"
            );
        }
        other => panic!("expected UnknownField, got {other:?}"),
    }
}

#[test]
fn an_unknown_top_level_section_is_rejected() {
    let err = Ruleset::from_toml(&format!("{}\n[nonsense]\nx = 1\n", header())).unwrap_err();
    assert!(
        matches!(err, RulesetError::UnknownField { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_missing_required_field_is_rejected_naming_the_rule() {
    let body = valid_rule().replace("severity = 85\n", "");
    let err = Ruleset::from_toml(&with_rule(&body)).unwrap_err();
    match err {
        RulesetError::MissingField { rule, field } => {
            assert_eq!(field, "severity");
            assert_eq!(rule.as_deref(), Some("override.ignore_previous"));
        }
        other => panic!("expected MissingField, got {other:?}"),
    }
}

#[test]
fn a_missing_description_is_rejected() {
    // Required rather than optional on purpose: an unexplained finding is one a user cannot act on.
    let body = valid_rule().replace(
        r#"description = "Instruction to disregard prior instructions.""#,
        "",
    );
    let err = Ruleset::from_toml(&with_rule(&body)).unwrap_err();
    assert!(
        matches!(&err, RulesetError::MissingField { field, .. } if field == "description"),
        "got {err:?}"
    );
}

#[test]
fn an_empty_description_is_rejected() {
    let body = valid_rule().replace(
        r#"description = "Instruction to disregard prior instructions.""#,
        r#"description = "   ""#,
    );
    let err = Ruleset::from_toml(&with_rule(&body)).unwrap_err();
    assert!(
        matches!(&err, RulesetError::MissingField { field, .. } if field == "description"),
        "got {err:?}"
    );
}

#[test]
fn a_wrongly_typed_field_is_rejected() {
    let body = valid_rule().replace("severity = 85", r#"severity = "high""#);
    let err = Ruleset::from_toml(&with_rule(&body)).unwrap_err();
    assert!(matches!(err, RulesetError::WrongType { .. }), "got {err:?}");
}

// ── Legality rejections ────────────────────────────────────────────────────────────────────────

#[test]
fn a_malformed_id_is_rejected() {
    for bad in [
        "nodot",
        "Upper.Case",
        "trailing.",
        "has space.x",
        "has-dash.x",
    ] {
        let body = valid_rule().replace("override.ignore_previous", bad);
        let err = Ruleset::from_toml(&with_rule(&body))
            .expect_err(&format!("{bad:?} should be rejected"));
        assert!(
            matches!(err, RulesetError::MalformedId { .. }),
            "{bad:?} gave {err:?}"
        );
    }
}

#[test]
fn a_duplicate_id_is_rejected() {
    let doc = format!(
        "{}\n[[rule]]{}\n[[rule]]{}",
        header(),
        valid_rule(),
        valid_rule()
    );
    let err = Ruleset::from_toml(&doc).unwrap_err();
    assert!(
        matches!(err, RulesetError::DuplicateId { .. }),
        "got {err:?}"
    );
}

#[test]
fn an_unknown_class_is_rejected() {
    let body = valid_rule().replace(r#"class = "override""#, r#"class = "vibes""#);
    let err = Ruleset::from_toml(&with_rule(&body)).unwrap_err();
    match err {
        RulesetError::UnknownClass { rule, class } => {
            assert_eq!(class, "vibes");
            assert_eq!(rule, "override.ignore_previous");
        }
        other => panic!("expected UnknownClass, got {other:?}"),
    }
}

#[test]
fn an_out_of_range_severity_is_rejected_reporting_what_was_written() {
    for bad in ["101", "255", "-1"] {
        let body = valid_rule().replace("severity = 85", &format!("severity = {bad}"));
        let err = Ruleset::from_toml(&with_rule(&body)).unwrap_err();
        assert!(
            matches!(err, RulesetError::SeverityOutOfRange { .. }),
            "severity {bad} gave {err:?}"
        );
    }
}

#[test]
fn non_ascending_bands_are_rejected() {
    let doc = format!("{}\n[bands]\nlow = 80\nmedium = 20\n", header());
    let err = Ruleset::from_toml(&doc).unwrap_err();
    assert!(
        matches!(err, RulesetError::BandsNotAscending { .. }),
        "got {err:?}"
    );
}

// ── Pattern rejections: the security-relevant ones ─────────────────────────────────────────────

#[test]
fn an_uncompilable_pattern_is_rejected() {
    let body = valid_rule().replace(r"pattern = '(?i)\bignore\b'", "pattern = '(unclosed'");
    let err = Ruleset::from_toml(&with_rule(&body)).unwrap_err();
    assert!(
        matches!(err, RulesetError::PatternInvalid { .. }),
        "got {err:?}"
    );
}

#[test]
fn lookaround_and_backreferences_cannot_be_written() {
    // Not rejected by a check of ours — the engine has no syntax for them. That absence is exactly what
    // guarantees every accepted rule matches in linear time (Principle II), so this test is really
    // asserting that we have not swapped in a backtracking engine.
    for pattern in [r"(?<=foo)bar", r"(?=foo)bar", r"(\w)\1"] {
        let body = valid_rule().replace(
            r"pattern = '(?i)\bignore\b'",
            &format!("pattern = '{pattern}'"),
        );
        let err = Ruleset::from_toml(&with_rule(&body))
            .expect_err(&format!("{pattern} should not compile"));
        assert!(
            matches!(err, RulesetError::PatternInvalid { .. }),
            "{pattern} gave {err:?}"
        );
    }
}

#[test]
fn an_oversized_pattern_source_is_rejected() {
    let huge = "a".repeat(1000);
    let body = valid_rule().replace(
        r"pattern = '(?i)\bignore\b'",
        &format!("pattern = '{huge}'"),
    );
    let err = Ruleset::from_toml(&with_rule(&body)).unwrap_err();
    assert!(
        matches!(err, RulesetError::PatternTooLong { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_counted_repetition_bomb_still_parses_cleanly() {
    // Twenty bytes of source, an enormous automaton. This is the one that makes a shared rule set a
    // memory-exhaustion path — and it is well-formed TOML containing a pattern that PARSES fine, so only
    // compilation catches it.
    //
    // What this test asserts is the *limitation*, not the protection: `Ruleset::from_toml` runs the cheap
    // tier only, so a bomb gets a `Ruleset`. That is fine, and stating it is useful, because a `Ruleset` is
    // no longer a scanning capability — `Engine` can only be built from a `PreparedRuleset`, and every
    // route to one validates (FR-102, FR-103).
    //
    // 001 asserted the same parse and then called `Ruleset::validate_compiled`, a public optional method
    // whose doc comment said "call this for any rule set you did not ship" and which nothing in the tree
    // called. The comment here even claimed "which is exactly what the CLI does for `--rules`"; the CLI has
    // no `--rules` flag. That method is gone from the public surface.
    //
    // The rejection is asserted in tests/preparation.rs, across every construction path (SC-101, SC-102).
    let body = valid_rule().replace(
        r"pattern = '(?i)\bignore\b'",
        "pattern = 'a{1000}{1000}{1000}'",
    );
    let limits = RulesetLimits {
        max_compiled_bytes: 64 * 1024,
        ..RulesetLimits::default()
    };

    Ruleset::from_toml_with_limits(&with_rule(&body), &limits)
        .expect("a size bomb parses cleanly — that is the whole point of the second tier");
}

#[test]
fn a_bomb_that_parsed_cannot_become_a_scanner() {
    // The other half, here rather than only in tests/preparation.rs because this file is where someone
    // reading about rule-set loading will look for it. Parsing and capability are now different things.
    let body = valid_rule().replace(
        r"pattern = '(?i)\bignore\b'",
        "pattern = 'a{1000}{1000}{1000}'",
    );
    let err = please_core::Engine::from_toml(&with_rule(&body)).unwrap_err();
    assert!(
        matches!(err, RulesetError::PatternTooComplex { .. }),
        "got {err:?}"
    );
}

#[test]
fn too_many_rules_is_rejected() {
    let limits = RulesetLimits {
        max_rules: 2,
        ..RulesetLimits::default()
    };
    let mut doc = header().to_string();
    for i in 0..3 {
        doc.push_str(&format!(
            "\n[[rule]]\nid = \"test.rule_{i}\"\nclass = \"override\"\nseverity = 10\n\
             literals = [\"x\"]\npattern = 'x'\ndescription = \"d\"\n"
        ));
    }
    let err = Ruleset::from_toml_with_limits(&doc, &limits).unwrap_err();
    assert!(
        matches!(err, RulesetError::TooManyRules { .. }),
        "got {err:?}"
    );
}

// ── Whole-or-nothing ───────────────────────────────────────────────────────────────────────────

#[test]
fn one_bad_rule_rejects_the_whole_set() {
    // A half-loaded rule set is indistinguishable from a deliberately weakened one, which is why
    // partial loading is never permitted.
    let doc = format!(
        "{}\n[[rule]]{}\n[[rule]]\nid = \"broken.rule\"\nclass = \"nonsense\"\nseverity = 10\n\
         pattern = 'x'\ndescription = \"d\"\n",
        header(),
        valid_rule()
    );
    assert!(
        Ruleset::from_toml(&doc).is_err(),
        "a set containing one invalid rule must not load at all"
    );
}

// ── Warnings ───────────────────────────────────────────────────────────────────────────────────

#[test]
fn a_rule_with_no_literals_loads_but_warns() {
    let body = valid_rule().replace("literals = [\"ignore\"]\n", "");
    let set = Ruleset::from_toml(&with_rule(&body)).expect("permitted");
    assert!(
        set.warnings().iter().any(|w| w.contains("no literals")),
        "expected a warning about the missing literal gate, got {:?}",
        set.warnings()
    );
}

// ── Determinism ────────────────────────────────────────────────────────────────────────────────

#[test]
fn digest_is_independent_of_file_order() {
    let a = format!(
        "{}\n[[rule]]\nid = \"a.one\"\nclass = \"override\"\nseverity = 10\nliterals = [\"x\"]\n\
         pattern = 'x'\ndescription = \"d\"\n\
         [[rule]]\nid = \"b.two\"\nclass = \"boundary\"\nseverity = 20\nliterals = [\"y\"]\n\
         pattern = 'y'\ndescription = \"d\"\n",
        header()
    );
    let b = format!(
        "{}\n[[rule]]\nid = \"b.two\"\nclass = \"boundary\"\nseverity = 20\nliterals = [\"y\"]\n\
         pattern = 'y'\ndescription = \"d\"\n\
         [[rule]]\nid = \"a.one\"\nclass = \"override\"\nseverity = 10\nliterals = [\"x\"]\n\
         pattern = 'x'\ndescription = \"d\"\n",
        header()
    );
    let one = Ruleset::from_toml(&a).unwrap();
    let two = Ruleset::from_toml(&b).unwrap();
    assert_eq!(
        one.id().digest,
        two.id().digest,
        "digest must describe content, not layout"
    );
}

#[test]
fn digest_changes_when_any_field_changes() {
    let base = Ruleset::from_toml(&with_rule(valid_rule())).unwrap();
    for tweak in [
        ("severity = 85", "severity = 86"),
        (r#"class = "override""#, r#"class = "boundary""#),
        (
            r"pattern = '(?i)\bignore\b'",
            r"pattern = '(?i)\bdisregard\b'",
        ),
        (r#"literals = ["ignore"]"#, r#"literals = ["disregard"]"#),
    ] {
        let body = valid_rule().replace(tweak.0, tweak.1);
        let other = Ruleset::from_toml(&with_rule(&body)).unwrap();
        assert_ne!(
            base.id().digest,
            other.id().digest,
            "changing {:?} must change the digest",
            tweak.0
        );
    }
}

// ── Resolution ─────────────────────────────────────────────────────────────────────────────────

fn addition() -> Ruleset {
    Ruleset::from_toml(
        r#"
[ruleset]
name = "acme.internal"
version = "1.0.0"

[[rule]]
id = "boundary.acme_tool_marker"
class = "boundary"
severity = 75
literals = ["<<<ACME_TOOL"]
pattern = '<<<ACME_TOOL[A-Z_]*>>>'
description = "Forged internal tool-result delimiter."
"#,
    )
    .expect("addition should load")
}

#[test]
fn an_addition_is_merged() {
    let base = Ruleset::from_toml(&with_rule(valid_rule())).unwrap();
    let resolved =
        Ruleset::resolve(base, vec![addition()], &[], &RulesetLimits::default()).unwrap();
    assert_eq!(resolved.len(), 2);
    assert!(resolved
        .all_rules()
        .iter()
        .any(|r| r.id == "boundary.acme_tool_marker"));
}

#[test]
fn an_addition_replacing_a_builtin_is_reported() {
    // Overriding a built-in rule must never be accidental.
    let base = Ruleset::from_toml(&with_rule(valid_rule())).unwrap();
    let override_body = valid_rule().replace("severity = 85", "severity = 10");
    let replacement = Ruleset::from_toml(&with_rule(&override_body)).unwrap();

    let resolved =
        Ruleset::resolve(base, vec![replacement], &[], &RulesetLimits::default()).unwrap();
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved.all_rules()[0].severity, 10, "addition should win");
    assert!(
        resolved.warnings().iter().any(|w| w.contains("replaced")),
        "replacement must be reported, got {:?}",
        resolved.warnings()
    );
}

#[test]
fn a_suppression_removes_the_rule() {
    let base = Ruleset::from_toml(&with_rule(valid_rule())).unwrap();
    let resolved = Ruleset::resolve(
        base,
        vec![],
        &["override.ignore_previous".to_string()],
        &RulesetLimits::default(),
    )
    .unwrap();
    assert!(resolved.is_empty());
}

#[test]
fn suppressing_an_unknown_rule_is_an_error_not_a_no_op() {
    // The usual cause is a typo, and a typo that quietly leaves a rule enabled defeats the entire
    // point of disabling it.
    let base = Ruleset::from_toml(&with_rule(valid_rule())).unwrap();
    let err = Ruleset::resolve(
        base,
        vec![],
        &["override.ignore_previus".to_string()],
        &RulesetLimits::default(),
    )
    .unwrap_err();
    match err {
        RulesetError::UnknownSuppression { id } => assert_eq!(id, "override.ignore_previus"),
        other => panic!("expected UnknownSuppression, got {other:?}"),
    }
}

#[test]
fn suppression_applies_after_additions() {
    // A rule can be added by one layer and switched off by another.
    let base = Ruleset::from_toml(header()).unwrap();
    let resolved = Ruleset::resolve(
        base,
        vec![addition()],
        &["boundary.acme_tool_marker".to_string()],
        &RulesetLimits::default(),
    )
    .unwrap();
    assert!(resolved.is_empty());
}

#[test]
fn resolution_changes_the_digest() {
    // SC-012: a verdict must be attributable to the exact rules that produced it, so adding or
    // suppressing anything has to move the identity.
    let base = Ruleset::from_toml(&with_rule(valid_rule())).unwrap();
    let before = base.id().digest.clone();
    let resolved =
        Ruleset::resolve(base, vec![addition()], &[], &RulesetLimits::default()).unwrap();
    assert_ne!(before, resolved.id().digest);
}

#[test]
fn resolution_enforces_the_rule_count_limit() {
    let base = Ruleset::from_toml(&with_rule(valid_rule())).unwrap();
    let limits = RulesetLimits {
        max_rules: 1,
        ..RulesetLimits::default()
    };
    let err = Ruleset::resolve(base, vec![addition()], &[], &limits).unwrap_err();
    assert!(
        matches!(err, RulesetError::TooManyRules { .. }),
        "got {err:?}"
    );
}

#[test]
fn a_disabled_rule_is_excluded_from_matching_but_kept_in_identity() {
    // "Present but off" is a different configuration from "absent", and the digest should say so.
    let body = valid_rule().replace("severity = 85", "severity = 85\nenabled = false");
    let set = Ruleset::from_toml(&with_rule(&body)).unwrap();
    assert_eq!(set.rules().count(), 0, "disabled rules do not match");
    assert_eq!(set.all_rules().len(), 1, "but remain part of the set");
}
