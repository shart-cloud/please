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
use crate::prepare::Provenance;

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

impl RulesetLimits {
    /// True when these limits allow everything `other` allows, and possibly more.
    ///
    /// The comparison a validation record needs (FR-108). Every field is a ceiling, so "at least as
    /// permissive" is a field-wise `>=` — and every field has to be checked, because a caller can raise one
    /// while lowering another and that combination is not covered by a record established at either.
    pub fn permits_at_least(&self, other: &RulesetLimits) -> bool {
        self.max_pattern_bytes >= other.max_pattern_bytes
            && self.max_compiled_bytes >= other.max_compiled_bytes
            && self.max_rules >= other.max_rules
    }
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

/// Where in a document's structure a rule is allowed to match.
///
/// # Why this is rule data rather than pattern syntax
///
/// Before feature 005 a rule anchored itself by writing the anchor into its own regex, as a line-start
/// assertion followed by a hand-written prefix character class:
///
/// ```text
/// ^[\s>*+\-•\d.)\]]{0,8}(\[|<\|)?(system|assistant)\s*(\]|\|>)?\s*:
/// ```
///
/// Two things were wrong with that, and only the second one is obvious.
///
/// **It is unreviewable.** Principle III says a rule's meaning must be reviewable in a pull request
/// without running it. Deciding whether that prefix class admits a markdown table cell requires reading
/// eleven escaped characters and knowing what the engine does with them. `anchor = "frame"` is one word.
///
/// **Every structured container introduces a prefix character nobody listed.** `<!--` for an HTML
/// comment, `|` for a table cell, `"` for a JSON string value. Each omission is a silent evasion, and
/// each is fixed by editing every rule that carries a copy of the class — which is how one defect came
/// to be recorded in `docs/limits.md` as two unrelated open rules, and how four copies of the same
/// hand-rolled frame alternation came to drift apart inside `rules/`.
///
/// Moving the anchor into data fixes the next container once instead of once per rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum Anchor {
    /// Match anywhere in live text. The default, and what a rule gets by saying nothing.
    #[default]
    Anywhere,
    /// Match only at a frame boundary — a position that begins a semantic unit.
    ///
    /// See [`crate::structure::StructureMap::is_frame`] for what counts as one.
    Frame,
}

impl Anchor {
    /// The wire name, as written in TOML and as hashed into the rule-set digest.
    pub fn as_str(self) -> &'static str {
        match self {
            Anchor::Anywhere => "anywhere",
            Anchor::Frame => "frame",
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
    /// Where in the document's structure this rule may match (005 FR-501).
    ///
    /// Sibling of `fires_in_quotes` in every sense: declarative, defaulted, and consumed by a filter in
    /// [`crate::detect`] rather than by the matcher. The two are independent and are applied in order —
    /// the frame decides whether a match was ever a finding, and suppression decides whether a finding
    /// is reported. A frame boundary inside a fenced block is still inside a fenced block.
    pub anchor: Anchor,
    pub enabled: bool,
    /// Why this rule exists. **Required**, and shown in output so a finding explains itself without a
    /// lookup — an unexplained finding is one a user cannot act on, and it is the first thing that
    /// erodes trust in a scanner.
    pub description: String,
    /// Where this rule came from (FR-105).
    ///
    /// Set when the rule is parsed, from the *source* rather than from anything in the rule, and carried
    /// through resolution unchanged. Per-rule rather than per-set, which is the whole point: after
    /// layering a caller's additions onto the built-in set you must still be able to say which half is
    /// untrusted, or delta validation collapses into validating everything.
    ///
    /// The field is public and that is safe, because the unforgeable thing is the *value*: a caller can
    /// write `provenance` freely and still cannot obtain a [`Provenance`] that reports `is_builtin`.
    pub provenance: Provenance,
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

    /// Set every rule's provenance.
    ///
    /// The expensive validation tier used to live here, as `validate_compiled`, and it is **gone from the
    /// public surface** (FR-103). It is now `crate::prepare`, which is reachable only by routes that run it
    /// — because while it existed as a separate call, some caller was always going to omit it, and in 001
    /// every caller did.
    ///
    /// This method is safe to expose despite what it does, and the reason is worth stating: it takes a
    /// [`Provenance`] the caller must already hold, and a caller cannot construct the trusted one. So the
    /// only stamp available outside `crate::prepare` is the stamp that causes *more* validation.
    ///
    /// Does not recompute the identity digest, and must not: content identity deliberately excludes
    /// provenance, so that "were these the same rules?" stays answerable independently of "did we trust
    /// them?". Trust enters identity one level up, in `PreparedRuleset::id` (FR-111).
    pub fn stamp_provenance(&mut self, provenance: Provenance) {
        for rule in &mut self.rules {
            rule.provenance = provenance;
        }
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
    ///
    /// **Provenance survives** (FR-105), and it survives by being a field of [`Rule`] rather than a
    /// property of the set: replacement swaps whole rules, so the surviving rule brings its own origin
    /// with it. That is what makes a caller replacing a built-in rule own the replacement — overriding a
    /// built-in id is not a way to inherit its trust — and it is what lets T039 validate the caller's
    /// half of the resolved set and leave the rest alone.
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
        // The anchor changes which text a rule matches, so two rule sets differing only in it are
        // different rule sets. A digest whose job is attribution has to say so (SC-012).
        hasher.update(rule.anchor.as_str().as_bytes());
        hasher.update([0]);
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
    UnknownAnchor {
        rule: String,
        anchor: String,
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
            Self::UnknownAnchor { rule, anchor } => write!(
                f,
                "rule `{rule}`: unknown anchor `{anchor}`. Expected `anywhere` or `frame`. \
                 An unrecognised anchor is rejected rather than defaulted, because defaulting it to \
                 `anywhere` would silently widen where the rule matches"
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
            anchor: Anchor::Anywhere,
            enabled: true,
            description: "d".into(),
            provenance: Provenance::supplied(),
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
