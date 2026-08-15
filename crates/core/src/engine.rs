//! The engine: a compiled rule set, ready to scan.
//!
//! Build one and reuse it. Compiling a rule set is the expensive part; scanning is the cheap part, and
//! the whole two-stage matching design exists so that the cheap part stays cheap (research D4).
//!
//! # What is deliberately absent
//!
//! No `async`. No clock. No filesystem. No network. A caller supplies bytes and gets a verdict, which
//! is what lets the same engine serve a pre-tool hook that must answer in milliseconds, a Rust harness
//! whose own constitution forbids a forced runtime, and a browser (Principle V).
//!
//! [`Engine::from_toml`] takes a string rather than a path for exactly that reason: rule-set *loading*
//! is I/O, and I/O belongs to the caller.

use crate::ruleset::{Ruleset, RulesetError, RulesetLimits};
use crate::verdict::RulesetId;

/// The built-in rule set, embedded at compile time.
///
/// Embedded rather than read from disk so that a first run needs no configuration, no filesystem, and
/// no network (FR-025, FR-031) — and so the same rule set works unchanged in a browser.
const BUILTIN_RULES: &str = include_str!("../../../rules/builtin.toml");

/// A compiled rule set, ready to scan.
///
/// `Send + Sync` by construction (it owns only owned data), so one engine can serve concurrent scans.
#[derive(Debug, Clone)]
pub struct Engine {
    ruleset: Ruleset,
}

impl Engine {
    /// The built-in rule set.
    ///
    /// Returns `Err` only if the embedded rule set is itself invalid, which is a build-time defect
    /// rather than a runtime condition — hence the accompanying test that loads it.
    pub fn builtin() -> Result<Self, RulesetError> {
        Ok(Self {
            ruleset: Ruleset::from_toml(BUILTIN_RULES)?,
        })
    }

    /// A rule set from TOML source, replacing the built-in entirely.
    pub fn from_toml(source: &str) -> Result<Self, RulesetError> {
        Ok(Self {
            ruleset: Ruleset::from_toml(source)?,
        })
    }

    /// Start from the built-in set and layer caller additions and suppressions on top.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    pub fn ruleset(&self) -> &Ruleset {
        &self.ruleset
    }

    /// Identity of the resolved rule set, recorded in every verdict (FR-005, SC-012).
    pub fn ruleset_id(&self) -> &RulesetId {
        self.ruleset.id()
    }

    /// Non-fatal observations from loading — a rule with no literal gate, a built-in replaced by an
    /// addition. Surfaced so overriding a rule is never accidental.
    pub fn warnings(&self) -> &[String] {
        self.ruleset.warnings()
    }
}

/// Layered rule-set construction (FR-023).
///
/// Resolution order is fixed: built-in, then additions, then suppressions last — so a rule can be
/// added by one layer and switched off by another.
#[derive(Debug, Default)]
pub struct EngineBuilder {
    base: Option<Ruleset>,
    additions: Vec<Ruleset>,
    suppress: Vec<String>,
    limits: RulesetLimits,
}

impl EngineBuilder {
    /// Replace the built-in base with a rule set of your own.
    pub fn base(mut self, ruleset: Ruleset) -> Self {
        self.base = Some(ruleset);
        self
    }

    /// Layer an additional rule set on top. A rule whose id matches an existing one replaces it, and
    /// the replacement is reported in [`Engine::warnings`].
    ///
    /// Named `add_ruleset` rather than `add` so it cannot be confused with `std::ops::Add::add`.
    pub fn add_ruleset(mut self, ruleset: Ruleset) -> Self {
        self.additions.push(ruleset);
        self
    }

    /// Disable a rule by id.
    ///
    /// Suppressing an id that does not exist is an **error** at build time, not a silent no-op: the
    /// usual cause is a typo, and a typo that quietly leaves a rule enabled defeats the point of
    /// disabling it.
    pub fn disable(mut self, rule_id: impl Into<String>) -> Self {
        self.suppress.push(rule_id.into());
        self
    }

    /// Override the resource limits enforced at load time.
    pub fn limits(mut self, limits: RulesetLimits) -> Self {
        self.limits = limits;
        self
    }

    pub fn build(self) -> Result<Engine, RulesetError> {
        let base = match self.base {
            Some(ruleset) => ruleset,
            None => Ruleset::from_toml_with_limits(BUILTIN_RULES, &self.limits)?,
        };
        let ruleset = Ruleset::resolve(base, self.additions, &self.suppress, &self.limits)?;
        Ok(Engine { ruleset })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_embedded_builtin_rule_set_loads() {
        // If this fails the build is shipping a rule set that cannot be parsed, which no amount of
        // downstream correctness recovers from.
        let engine = Engine::builtin().expect("embedded builtin must load");
        assert_eq!(engine.ruleset_id().name, "please.builtin");
        assert_eq!(engine.ruleset_id().digest.len(), 16);
    }

    #[test]
    fn the_builtin_digest_is_stable_across_builds() {
        // Two loads of the same embedded source must agree, or verdict attribution is meaningless.
        let a = Engine::builtin().unwrap();
        let b = Engine::builtin().unwrap();
        assert_eq!(a.ruleset_id().digest, b.ruleset_id().digest);
    }

    #[test]
    fn builder_defaults_to_the_builtin_set() {
        let engine = Engine::builder().build().unwrap();
        assert_eq!(engine.ruleset_id().name, "please.builtin");
    }

    #[test]
    fn builder_rejects_suppressing_an_unknown_rule() {
        let err = Engine::builder()
            .disable("nonsense.rule")
            .build()
            .unwrap_err();
        assert!(
            matches!(err, RulesetError::UnknownSuppression { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn engine_is_send_and_sync() {
        // One engine serves concurrent scans (contracts/core-api.md). Asserted at compile time so the
        // guarantee cannot regress by someone adding an interior-mutable field.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<Engine>();
    }
}
