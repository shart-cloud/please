//! Load-time validation: legality and resource limits (FR-024).
//!
//! Parsing established that the document has the right shape. This establishes that its contents are
//! legal *and* that loading it cannot hurt the host — because a rule set is caller-supplied and
//! therefore untrusted input to the scanner (FR-023).
//!
//! Compilation happens here rather than lazily at match time. That is a deliberate trade against the
//! lazy-compilation design used for *matching*: a pattern that would blow up the compiler must be
//! rejected before it is accepted into a rule set, not discovered on the first input that happens to
//! contain its literal. Load once, loudly; match many times, cheaply.
//!
//! Every check rejects the **whole** set. A half-loaded rule set is indistinguishable from a
//! deliberately weakened one.

use super::parse::{RawRule, RawRuleset};
use super::{Rule, Ruleset, RulesetError, RulesetLimits};
use crate::verdict::DetectionClass;

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

    compile_check(&raw.id, &raw.pattern, limits)?;

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
        enabled: raw.enabled,
        description: raw.description,
    })
}

/// Compile the pattern under a size limit, discarding the result.
///
/// Two distinct failures come out of this, and they deserve distinct diagnostics:
///
/// * **Invalid syntax**, which includes any use of look-around or backreferences. Those are not
///   supported by the engine, which is precisely why every accepted pattern matches in linear time —
///   an author cannot write a catastrophically backtracking rule because the syntax has no way to say
///   it.
/// * **Exceeding the compiled-size limit**, which is the counted-repetition expansion case:
///   `a{5}{5}{5}{5}{5}{5}` is twenty bytes of source and an enormous automaton. Without this limit a
///   rule set copied from an untrusted source is a memory-exhaustion path into the scanner.
fn compile_check(id: &str, pattern: &str, limits: &RulesetLimits) -> Result<(), RulesetError> {
    match regex::RegexBuilder::new(pattern)
        .size_limit(limits.max_compiled_bytes)
        .build()
    {
        Ok(_) => Ok(()),
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
        "encoding" => DetectionClass::Encoding,
        "boundary" => DetectionClass::Boundary,
        "solicitation" => DetectionClass::Solicitation,
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
    fn lookaround_is_not_expressible() {
        // Not a check we implement — the engine simply has no syntax for it, which is what makes every
        // accepted pattern linear-time.
        let limits = RulesetLimits::default();
        assert!(compile_check("t.t", r"(?<=foo)bar", &limits).is_err());
        assert!(compile_check("t.t", r"(\w)\1", &limits).is_err());
    }

    #[test]
    fn counted_repetition_bomb_exceeds_the_size_limit() {
        let limits = RulesetLimits {
            max_compiled_bytes: 4096,
            ..RulesetLimits::default()
        };
        let err = compile_check("t.t", "a{100}{100}{100}", &limits).unwrap_err();
        assert!(
            matches!(err, RulesetError::PatternTooComplex { .. }),
            "expected PatternTooComplex, got {err:?}"
        );
    }
}
