//! Load-time validation: legality and resource limits (FR-024).
//!
//! Parsing established that the document has the right shape. This establishes that its contents are
//! legal *and* that loading it cannot hurt the host — because a rule set is caller-supplied and
//! therefore untrusted input to the scanner (FR-023).
//!
//! # Why validation is in two tiers
//!
//! Measured on 80 representative rules (research D17):
//!
//! | Check | Cost | Catches |
//! |---|---|---|
//! | Syntax parse | ~3.9 ms | look-around, backreferences, malformed patterns |
//! | Full compile | ~44 ms | the above, plus counted-repetition size bombs |
//!
//! 44 ms is 1.8x the entire cold-start budget, and the consumer is a hook that launches the binary
//! once per tool call. So loading does the cheap tier always, and the expensive tier is explicit:
//!
//! * [`syntax_check`] runs on every load. It rejects everything a *malformed* rule can be, which is
//!   the FR-024 case, at a cost that fits the budget.
//! * [`super::Ruleset::validate_compiled`] compiles every pattern under a size limit and is called
//!   where a rule set is genuinely untrusted — the CLI accepting `--rules` — and by a test over the
//!   embedded built-in set. It is where a size bomb is caught.
//!
//! The built-in set is not attacker-controlled: it ships inside the binary, and a CI test proves it
//! passes the expensive tier. Paying 44 ms on every invocation to re-establish that would be paying for
//! a guarantee already held.
//!
//! Every check rejects the **whole** set. A half-loaded rule set is indistinguishable from a
//! deliberately weakened one.

use super::parse::{RawRule, RawRuleset};
use super::{Anchor, Rule, Ruleset, RulesetError, RulesetLimits};
use crate::finalize::types::DetectionClass;
use crate::prepare::Provenance;

pub(super) fn validate(raw: RawRuleset, limits: &RulesetLimits) -> Result<Ruleset, RulesetError> {
    raw.bands.validate()?;

    if raw.rules.len() > limits.max_rules {
        return Err(RulesetError::TooManyRules {
            count: raw.rules.len(),
            limit: limits.max_rules,
        });
    }

    let mut rules: Vec<Rule> = Vec::with_capacity(raw.rules.len());
    let mut warnings: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();

    for raw_rule in raw.rules {
        let rule = validate_rule(raw_rule, limits, &mut warnings)?;
        if seen.contains(&rule.id) {
            return Err(RulesetError::DuplicateId { id: rule.id });
        }
        seen.push(rule.id.clone());
        rules.push(rule);
    }

    // Deterministic order independent of file order, so the digest describes content rather than
    // layout (SC-011, SC-012).
    rules.sort_by(|a, b| a.id.cmp(&b.id));

    Ok(Ruleset::assemble(
        raw.name,
        raw.version,
        rules,
        raw.bands,
        warnings,
    ))
}

fn validate_rule(
    raw: RawRule,
    limits: &RulesetLimits,
    warnings: &mut Vec<String>,
) -> Result<Rule, RulesetError> {
    if !is_valid_id(&raw.id) {
        return Err(RulesetError::MalformedId { id: raw.id });
    }

    let class = parse_class(&raw.class).ok_or_else(|| RulesetError::UnknownClass {
        rule: raw.id.clone(),
        class: raw.class.clone(),
    })?;

    let anchor = match raw.anchor.as_str() {
        "anywhere" => Anchor::Anywhere,
        "frame" => Anchor::Frame,
        _ => {
            return Err(RulesetError::UnknownAnchor {
                rule: raw.id.clone(),
                anchor: raw.anchor.clone(),
            })
        }
    };

    let severity = u8::try_from(raw.severity)
        .ok()
        .filter(|s| *s <= 100)
        .ok_or_else(|| RulesetError::SeverityOutOfRange {
            rule: raw.id.clone(),
            severity: raw.severity,
        })?;

    if raw.pattern.len() > limits.max_pattern_bytes {
        return Err(RulesetError::PatternTooLong {
            rule: raw.id.clone(),
            bytes: raw.pattern.len(),
            limit: limits.max_pattern_bytes,
        });
    }

    syntax_check(&raw.id, &raw.pattern)?;

    if raw.literals.is_empty() {
        // Permitted, but expensive: a rule with no literal gate is evaluated against every input, and
        // a handful of them reintroduces the eager-compilation cost the two-stage design avoids.
        warnings.push(format!(
            "rule `{}` has no literals and will be evaluated against every input",
            raw.id
        ));
    }

    if raw.description.trim().is_empty() {
        return Err(RulesetError::MissingField {
            rule: Some(raw.id),
            field: "description".to_string(),
        });
    }

    Ok(Rule {
        id: raw.id,
        class,
        severity,
        literals: raw.literals,
        pattern: raw.pattern,
        fires_in_quotes: raw.fires_in_quotes,
        anchor,
        enabled: raw.enabled,
        description: raw.description,
        // Anything reaching this function came from TOML a caller handed us, so it is `Supplied`
        // (FR-105). The embedded rule set goes through here too and is re-stamped `Builtin` afterwards,
        // by preparation, which is the only thing that can. Defaulting the other way round -- stamp
        // trusted, downgrade later -- would mean any new loading path that forgot to downgrade would
        // silently skip validation.
        provenance: Provenance::supplied(),
    })
}

/// Parse the pattern without building an automaton. The cheap tier, run on every load.
///
/// Rejects any use of look-around or backreferences — not because we check for them, but because the
/// syntax has no way to express them. That absence is exactly why every accepted pattern matches in
/// linear time: an author cannot write a catastrophically backtracking rule (Principle II).
///
/// Does **not** catch a counted-repetition size bomb: `a{1000}{1000}{1000}` parses fine in 3.8 µs and
/// only explodes when compiled. That is [`compiled_check`]'s job.
pub(super) fn syntax_check(id: &str, pattern: &str) -> Result<(), RulesetError> {
    regex_syntax::parse(pattern)
        .map(|_| ())
        .map_err(|e| RulesetError::PatternInvalid {
            rule: id.to_string(),
            detail: e.to_string(),
        })
}

// The expensive tier used to live here as `compiled_check`, discarding the compiled result. It is now
// `crate::prepare::validate::compile_within`, which keeps it (T038, FR-109). The move is not tidying: while
// it lived beside the cheap tier it was reachable as an optional public call, and the whole US1 defect is
// that being reachable-but-optional means being skipped.

/// `^[a-z0-9_]+(\.[a-z0-9_]+)+$` — checked by hand so rule loading needs no regex of its own.
fn is_valid_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 {
        return false;
    }
    let segments: Vec<&str> = id.split('.').collect();
    if segments.len() < 2 {
        return false;
    }
    segments.iter().all(|segment| {
        !segment.is_empty()
            && segment
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    })
}

fn parse_class(name: &str) -> Option<DetectionClass> {
    Some(match name {
        "override" => DetectionClass::Override,
        "concealment" => DetectionClass::Concealment,
        "confusable" => DetectionClass::Confusable,
        "boundary" => DetectionClass::Boundary,
        "solicitation" => DetectionClass::Solicitation,
        "agent_directed" => DetectionClass::AgentDirected,
        "external_action" => DetectionClass::ExternalAction,
        "privilege" => DetectionClass::Privilege,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_shape_is_enforced() {
        for good in [
            "override.ignore_previous",
            "a.b",
            "acme.internal.tool_marker",
            "x9._1",
        ] {
            assert!(is_valid_id(good), "{good} should be valid");
        }
        for bad in [
            "",
            "nodot",
            "Upper.Case",
            "trailing.",
            ".leading",
            "double..dot",
            "has space.x",
            "has-dash.x",
        ] {
            assert!(!is_valid_id(bad), "{bad:?} should be invalid");
        }
    }

    #[test]
    fn every_class_name_round_trips() {
        for class in crate::policy::ALL_CLASSES {
            assert_eq!(
                parse_class(class.as_str()),
                Some(class),
                "class name {:?} must parse back to itself",
                class.as_str()
            );
        }
        assert_eq!(parse_class("nonsense"), None);
    }

    #[test]
    fn lookaround_is_not_expressible_and_the_cheap_tier_catches_it() {
        // Not a check we implement — the engine simply has no syntax for it, which is what makes every
        // accepted pattern linear-time. Caught by parsing alone, so it costs nothing at load.
        assert!(syntax_check("t.t", r"(?<=foo)bar").is_err());
        assert!(syntax_check("t.t", r"(?=foo)bar").is_err());
        assert!(syntax_check("t.t", r"(\w)\1").is_err());
        assert!(syntax_check("t.t", r"(unclosed").is_err());
        assert!(syntax_check("t.t", r"(?i)\bignore\b").is_ok());
    }

    #[test]
    fn the_cheap_tier_does_not_catch_a_size_bomb() {
        // Stated as a test so the limitation is recorded rather than assumed. This is the entire reason
        // compiled_check exists and why an untrusted rule set must go through it.
        assert!(
            syntax_check("t.t", "a{1000}{1000}{1000}").is_ok(),
            "if this ever fails, the expensive tier may no longer be needed — re-measure D17"
        );
    }

    // `counted_repetition_bomb_exceeds_the_size_limit` moved with the expensive tier, to
    // prepare::validate::tests::a_counted_repetition_bomb_exceeds_the_size_limit (T038). Recorded in
    // docs/002-test-inventory-before.txt.
}
