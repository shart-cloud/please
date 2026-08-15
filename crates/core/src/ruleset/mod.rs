//! Rule sets: declarative detection definitions, loaded at run time (Principle III).
//!
//! A rule is the unit a reviewer reads in a pull request to understand what the scanner does. That is
//! why rules are data rather than Rust: the rule corpus is the part of a detector that changes weekly
//! and that users need to audit, extend, and override, and rules buried in code are neither reviewable
//! by the people who must trust them nor updatable without a release.
//!
//! # A rule set is untrusted input
//!
//! Callers may supply their own rules (FR-023), which makes a rule set an input to the scanner rather
//! than part of it. The pattern `a{5}{5}{5}{5}{5}{5}` is twenty characters of source that expands to
//! `a{15625}` and a correspondingly enormous automaton — so a rule set copied from a third party is a
//! memory-exhaustion path into the very tool meant to prevent that class of thing. Compilation is
//! therefore bounded, and every limit in [`RulesetLimits`] is enforced at load time.
//!
//! Two properties come free from the matching engine rather than from checks here:
//!
//! * **Look-around and backreferences cannot be written.** The syntax has no way to express them, so a
//!   catastrophically backtracking pattern fails to compile and therefore fails to load. Principle II
//!   is enforced structurally, not by review.
//! * **Every accepted pattern is linear-time.** There is no such thing as a pattern that loads and
//!   then behaves pathologically.
//!
//! # Whole or nothing
//!
//! A rule set is accepted entirely or rejected entirely. Partial loading is never permitted, because a
//! half-loaded rule set is indistinguishable from a deliberately weakened one — a typo that silently
//! disables a detection is worse than a hard failure that names it.

mod parse;
mod validate;

use crate::finalize::types::{DetectionClass, RiskLevel, RulesetId};

/// Resource limits enforced when a rule set is loaded.
///
/// Defaults are generous for legitimate rules and far below anything that threatens the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetLimits {
    /// Maximum bytes of pattern source. Bounds what can be handed to the compiler at all.
    pub max_pattern_bytes: usize,
    /// Maximum size of a compiled pattern's program, in bytes. This is the limit that actually stops
    /// counted-repetition expansion, since a short source can compile to an enormous automaton.
    pub max_compiled_bytes: usize,
    /// Maximum rules in one resolved set.
    pub max_rules: usize,
}

impl Default for RulesetLimits {
    fn default() -> Self {
        Self {
            max_pattern_bytes: 512,
            max_compiled_bytes: 1024 * 1024,
            max_rules: 1024,
        }
    }
}

/// Score thresholds mapping to risk bands.
///
/// Data rather than code so a deployment can retune without a rebuild. Values are **provisional**
/// until the evaluation harness calibrates them against per-source corpus metrics; `docs/limits.md`
/// says so rather than implying a calibration that has not happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bands {
    pub low: u8,
    pub medium: u8,
    pub high: u8,
    pub critical: u8,
}

impl Default for Bands {
    fn default() -> Self {
        Self {
            low: 20,
            medium: 45,
            high: 70,
            critical: 90,
        }
    }
}

impl Bands {
    /// The band a score falls into.
    pub fn band(&self, score: u8) -> RiskLevel {
        if score >= self.critical {
            RiskLevel::Critical
        } else if score >= self.high {
            RiskLevel::High
        } else if score >= self.medium {
            RiskLevel::Medium
        } else if score >= self.low {
            RiskLevel::Low
        } else {
            RiskLevel::None
        }
    }

    /// Ascending boundaries are a load-time requirement: a non-monotonic table makes banding
    /// order-dependent, so two implementations of the same table could disagree.
    fn validate(&self) -> Result<(), RulesetError> {
        if self.low <= self.medium && self.medium <= self.high && self.high <= self.critical {
            Ok(())
        } else {
            Err(RulesetError::BandsNotAscending {
                detail: format!(
                    "low={} medium={} high={} critical={}",
                    self.low, self.medium, self.high, self.critical
                ),
            })
        }
    }
}

/// One declarative detection definition.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Namespaced identifier, e.g. `override.ignore_previous`. Also the suppression handle, so it must
    /// be unambiguous.
    pub id: String,
    pub class: DetectionClass,
    pub severity: u8,
    /// Required literals gating this rule. All rules' literals go into one automaton; a rule's pattern
    /// is compiled only if one of its literals is present, so text matching nothing compiles nothing.
    ///
    /// An empty list means the rule is evaluated against every input. Permitted, but the loader warns:
    /// a handful of such rules reintroduces the eager-compilation cost the design exists to avoid.
    pub literals: Vec<String>,
    pub pattern: String,
    /// Whether this rule survives the quoting pre-pass (FR-014).
    pub fires_in_quotes: bool,
    pub enabled: bool,
    /// Why this rule exists. **Required**, and shown in output so a finding explains itself without a
    /// lookup — an unexplained finding is one a user cannot act on, and it is the first thing that
    /// erodes trust in a scanner.
    pub description: String,
}

/// A versioned, identified collection of rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ruleset {
    id: RulesetId,
    rules: Vec<Rule>,
    bands: Bands,
    warnings: Vec<String>,
}

impl Ruleset {
    /// Parse and validate a rule set with default limits.
    pub fn from_toml(source: &str) -> Result<Self, RulesetError> {
        Self::from_toml_with_limits(source, &RulesetLimits::default())
    }

    /// Parse and validate a rule set, enforcing `limits`.
    pub fn from_toml_with_limits(
        source: &str,
        limits: &RulesetLimits,
    ) -> Result<Self, RulesetError> {
        let parsed = parse::parse(source)?;
        validate::validate(parsed, limits)
    }

    /// Build from already-validated parts. Used by parsing and resolution; the digest is computed here
    /// so there is exactly one definition of what a rule set's identity covers.
    fn assemble(
        name: String,
        version: String,
        rules: Vec<Rule>,
        bands: Bands,
        warnings: Vec<String>,
    ) -> Self {
        let digest = digest_of(&name, &version, &rules, &bands);
        Self {
            id: RulesetId {
                name,
                version,
                digest,
            },
            rules,
            bands,
            warnings,
        }
    }

    pub fn id(&self) -> &RulesetId {
        &self.id
    }

    /// Enabled rules only. A disabled rule stays in the digest — the identity records what was
    /// *resolved*, and "this rule was present but off" is a different configuration from "this rule was
    /// absent".
    pub fn rules(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter().filter(|r| r.enabled)
    }

    /// Every rule, enabled or not.
    pub fn all_rules(&self) -> &[Rule] {
        &self.rules
    }

    pub fn bands(&self) -> &Bands {
        &self.bands
    }

    /// The expensive validation tier: compile every pattern under the size limit.
    ///
    /// **Call this for any rule set you did not ship.** Loading runs a cheap syntax-only check that
    /// rejects malformed patterns, look-around, and backreferences, but a counted-repetition size bomb
    /// parses fine in microseconds and only explodes when compiled — so this is where
    /// `a{1000}{1000}{1000}` is caught.
    ///
    /// It is separate because it is expensive: ~44 ms for 80 rules, against a 25 ms cold-start budget
    /// for the whole process (research D17). Paying it on every invocation would spend the budget
    /// re-establishing a guarantee the built-in set already holds via a CI test. Paying it once, when a
    /// caller supplies `--rules`, puts the cost where the untrusted input is.
    pub fn validate_compiled(&self, limits: &RulesetLimits) -> Result<(), RulesetError> {
        for rule in &self.rules {
            validate::compiled_check(&rule.id, &rule.pattern, limits)?;
        }
        Ok(())
    }

    /// Non-fatal observations from loading, e.g. a rule with no literals, or an addition replacing a
    /// built-in. Surfaced so overriding a rule is never accidental.
    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Resolve a built-in set against caller additions and suppressions (FR-023).
    ///
    /// Order is fixed: built-in, then additions, then suppressions last — so a rule can be added by one
    /// layer and switched off by another.
    ///
    /// An addition whose id matches an existing rule **replaces** it, and the replacement is recorded
    /// as a warning. Suppressing an unknown id is an **error**, not a silent no-op: the overwhelmingly
    /// common cause is a typo, and a typo that quietly leaves a rule enabled defeats the entire point
    /// of disabling it.
    pub fn resolve(
        base: Ruleset,
        additions: Vec<Ruleset>,
        suppress: &[String],
        limits: &RulesetLimits,
    ) -> Result<Ruleset, RulesetError> {
        let mut rules = base.rules;
        let mut warnings = base.warnings;
        let name = base.id.name;
        let version = base.id.version;
        let bands = base.bands;

        for addition in additions {
            warnings.extend(addition.warnings);
            for rule in addition.rules {
                match rules.iter().position(|existing| existing.id == rule.id) {
                    Some(index) => {
                        warnings.push(format!(
                            "rule `{}` replaced by an addition from `{}`",
                            rule.id, addition.id.name
                        ));
                        rules[index] = rule;
                    }
                    None => rules.push(rule),
                }
            }
        }

        for id in suppress {
            match rules.iter().position(|rule| &rule.id == id) {
                Some(index) => {
                    rules.remove(index);
                }
                None => return Err(RulesetError::UnknownSuppression { id: id.clone() }),
            }
        }

        if rules.len() > limits.max_rules {
            return Err(RulesetError::TooManyRules {
                count: rules.len(),
                limit: limits.max_rules,
            });
        }

        // Deterministic order regardless of how layers were supplied, so the digest depends on the
        // resolved content rather than on argument order (SC-011, SC-012).
        rules.sort_by(|a, b| a.id.cmp(&b.id));

        Ok(Ruleset::assemble(name, version, rules, bands, warnings))
    }
}

/// Content digest over a resolved rule set.
///
/// Covers every field that changes what the scanner does, so two verdicts reporting the same digest
/// really were produced by the same rules (SC-012).
///
/// SHA-256, truncated to 16 hex characters for legibility. Deliberately **not**
/// `std::hash::DefaultHasher`: that explicitly does not promise stability across Rust releases, so an
/// identity built on it would silently fork every stored verdict's attribution on a toolchain upgrade.
/// A digest whose job is attribution has to outlive the compiler that produced it.
fn digest_of(name: &str, version: &str, rules: &[Rule], bands: &Bands) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(name.as_bytes());
    hasher.update([0]);
    hasher.update(version.as_bytes());
    hasher.update([0]);
    hasher.update(
        format!(
            "{}:{}:{}:{}",
            bands.low, bands.medium, bands.high, bands.critical
        )
        .as_bytes(),
    );
    hasher.update([0]);

    for rule in rules {
        hasher.update(rule.id.as_bytes());
        hasher.update([0]);
        hasher.update(rule.class.as_str().as_bytes());
        hasher.update([0]);
        hasher.update([rule.severity]);
        hasher.update(rule.pattern.as_bytes());
        hasher.update([0]);
        for literal in &rule.literals {
            hasher.update(literal.as_bytes());
            hasher.update([0]);
        }
        hasher.update([u8::from(rule.fires_in_quotes), u8::from(rule.enabled)]);
        hasher.update(rule.description.as_bytes());
        hasher.update([0]);
    }

    let full = hasher.finalize();
    full.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Why a rule set was rejected.
///
/// Every variant names the offending rule where one exists. A diagnostic that says "invalid rule set"
/// without saying which rule is a diagnostic that costs someone an afternoon.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum RulesetError {
    Toml {
        detail: String,
    },
    MissingField {
        rule: Option<String>,
        field: String,
    },
    UnknownField {
        rule: Option<String>,
        field: String,
    },
    WrongType {
        rule: Option<String>,
        field: String,
        expected: &'static str,
    },
    MalformedId {
        id: String,
    },
    DuplicateId {
        id: String,
    },
    UnknownClass {
        rule: String,
        class: String,
    },
    SeverityOutOfRange {
        rule: String,
        severity: i64,
    },
    PatternTooLong {
        rule: String,
        bytes: usize,
        limit: usize,
    },
    /// Includes any use of look-around or backreferences, which the engine cannot express.
    PatternInvalid {
        rule: String,
        detail: String,
    },
    /// A pattern that compiled to a program larger than the limit — the counted-repetition
    /// expansion case.
    PatternTooComplex {
        rule: String,
        limit: usize,
    },
    TooManyRules {
        count: usize,
        limit: usize,
    },
    BandsNotAscending {
        detail: String,
    },
    UnknownSuppression {
        id: String,
    },
}

impl core::fmt::Display for RulesetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        fn at(rule: &Option<String>) -> String {
            match rule {
                Some(id) => format!("rule `{id}`"),
                None => "rule set".to_string(),
            }
        }
        match self {
            Self::Toml { detail } => write!(f, "rule set is not valid TOML: {detail}"),
            Self::MissingField { rule, field } => {
                write!(f, "{}: missing required field `{field}`", at(rule))
            }
            Self::UnknownField { rule, field } => write!(
                f,
                "{}: unknown field `{field}`. Unknown fields are rejected rather than ignored, \
                 because a typo that silently disables a detection is worse than a hard failure",
                at(rule)
            ),
            Self::WrongType {
                rule,
                field,
                expected,
            } => write!(f, "{}: field `{field}` must be {expected}", at(rule)),
            Self::MalformedId { id } => write!(
                f,
                "malformed rule id `{id}`: expected lowercase dotted segments, e.g. \
                 `override.ignore_previous`"
            ),
            Self::DuplicateId { id } => write!(
                f,
                "duplicate rule id `{id}`: identity is the suppression handle and must be unambiguous"
            ),
            Self::UnknownClass { rule, class } => write!(
                f,
                "rule `{rule}`: unknown detection class `{class}`. A rule in an unknown class could \
                 never be reported on or disabled"
            ),
            Self::SeverityOutOfRange { rule, severity } => {
                write!(f, "rule `{rule}`: severity {severity} outside 0..=100")
            }
            Self::PatternTooLong { rule, bytes, limit } => write!(
                f,
                "rule `{rule}`: pattern source is {bytes} bytes, limit is {limit}"
            ),
            Self::PatternInvalid { rule, detail } => write!(
                f,
                "rule `{rule}`: pattern does not compile: {detail}. Note that look-around and \
                 backreferences are not expressible — that absence is what guarantees linear-time \
                 matching"
            ),
            Self::PatternTooComplex { rule, limit } => write!(
                f,
                "rule `{rule}`: pattern compiles to a program exceeding {limit} bytes. A short \
                 pattern can expand enormously via counted repetition, which is why this limit exists"
            ),
            Self::TooManyRules { count, limit } => {
                write!(f, "rule set has {count} rules, limit is {limit}")
            }
            Self::BandsNotAscending { detail } => {
                write!(f, "band boundaries must ascend: {detail}")
            }
            Self::UnknownSuppression { id } => write!(
                f,
                "cannot suppress unknown rule `{id}`. This is an error rather than a no-op because \
                 the usual cause is a typo, and a typo that leaves a rule enabled defeats the point \
                 of disabling it"
            ),
        }
    }
}

impl std::error::Error for RulesetError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bands_map_scores_to_levels() {
        let b = Bands::default();
        assert_eq!(b.band(0), RiskLevel::None);
        assert_eq!(b.band(19), RiskLevel::None);
        assert_eq!(b.band(20), RiskLevel::Low);
        assert_eq!(b.band(45), RiskLevel::Medium);
        assert_eq!(b.band(70), RiskLevel::High);
        assert_eq!(b.band(90), RiskLevel::Critical);
        assert_eq!(b.band(100), RiskLevel::Critical);
    }

    #[test]
    fn non_ascending_bands_are_rejected() {
        let b = Bands {
            low: 50,
            medium: 20,
            high: 70,
            critical: 90,
        };
        assert!(b.validate().is_err());
    }

    #[test]
    fn digest_is_stable_and_content_sensitive() {
        let rule = Rule {
            id: "a.b".into(),
            class: DetectionClass::Override,
            severity: 50,
            literals: vec!["x".into()],
            pattern: "x".into(),
            fires_in_quotes: false,
            enabled: true,
            description: "d".into(),
        };
        let one = digest_of("n", "1", std::slice::from_ref(&rule), &Bands::default());
        let same = digest_of("n", "1", std::slice::from_ref(&rule), &Bands::default());
        assert_eq!(one, same, "digest must be stable for identical content");
        assert_eq!(one.len(), 16);

        let mut changed = rule.clone();
        changed.severity = 51;
        let other = digest_of("n", "1", &[changed], &Bands::default());
        assert_ne!(one, other, "digest must change when a rule changes");
    }
}
