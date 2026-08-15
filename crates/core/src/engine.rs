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

use crate::decode;
use crate::detect::{self, pattern::PatternSet};
use crate::finalize::evidence::{Evidence, Observation};
use crate::finalize::plan::ScanPlan;
use crate::finalize::score::aggregate;
use crate::finalize::types::{DetectionClass, RulesetId, TargetRef, Verdict};
use crate::finalize::{self, Attribution};
use crate::policy::ScanPolicy;
use crate::prefilter::Prefilter;
use crate::ruleset::{Ruleset, RulesetError, RulesetLimits};
use crate::sanitize::sanitize_bytes;
use crate::structure::QuotingMap;

/// The built-in rule set, embedded at compile time.
///
/// Embedded rather than read from disk so that a first run needs no configuration, no filesystem, and
/// no network (FR-025, FR-031) — and so the same rule set works unchanged in a browser.
const BUILTIN_RULES: &str = include_str!("../../../rules/builtin.toml");

/// A compiled rule set, ready to scan.
///
/// `Send + Sync`, so one engine serves concurrent scans. Deliberately **not** `Clone`: it holds a
/// memoisation cache of compiled patterns, and cloning would silently discard the work and re-pay
/// compilation on the copy. Share it behind an `Arc` instead — which is what a harness holding one
/// engine for the process wants anyway.
#[derive(Debug)]
pub struct Engine {
    ruleset: Ruleset,
    prefilter: Prefilter,
    patterns: PatternSet,
    limits: RulesetLimits,
}

impl Engine {
    /// The built-in rule set.
    ///
    /// Returns `Err` only if the embedded rule set is itself invalid, which is a build-time defect
    /// rather than a runtime condition — hence the accompanying test that loads it.
    pub fn builtin() -> Result<Self, RulesetError> {
        Ok(Self::from_ruleset(
            Ruleset::from_toml(BUILTIN_RULES)?,
            RulesetLimits::default(),
        ))
    }

    /// A rule set from TOML source, replacing the built-in entirely.
    ///
    /// Loading runs the cheap validation tier. A caller accepting a rule set it did not ship should also
    /// call [`Ruleset::validate_compiled`] — that is where a counted-repetition size bomb is caught
    /// (research D17).
    pub fn from_toml(source: &str) -> Result<Self, RulesetError> {
        Ok(Self::from_ruleset(
            Ruleset::from_toml(source)?,
            RulesetLimits::default(),
        ))
    }

    /// Build the matching machinery for an already-validated rule set.
    fn from_ruleset(ruleset: Ruleset, limits: RulesetLimits) -> Self {
        let prefilter = Prefilter::build(ruleset.all_rules());
        let patterns = PatternSet::new(ruleset.all_rules().len(), limits.clone());
        Self {
            ruleset,
            prefilter,
            patterns,
            limits,
        }
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

    /// Scan bytes and return a verdict.
    ///
    /// **Infallible by design.** Everything that could be an error is instead an outcome the caller must
    /// read: oversized input, an uncompilable rule, an unavailable tier. There is no `Err` for an
    /// embedder to `unwrap_or_default()` into a clean verdict — the type system offers no path from
    /// "analysis failed" to "input is fine" (Principle I).
    ///
    /// Takes `&[u8]` rather than `&str` because scan targets are untrusted and frequently not valid
    /// UTF-8. Requiring text would force the caller into a lossy conversion or a rejection *before*
    /// analysis, and "this was not valid text" is a fact to report rather than a reason to refuse to look
    /// (FR-019).
    ///
    /// # Pipeline
    ///
    /// ```text
    /// size gate → decode → structure → prefilter → patterns → suppression → finalize
    /// ```
    ///
    /// Every stage may only *add* observations or record coverage gaps into the evidence accumulator;
    /// none may remove them, and none may read them back. That monotonicity plus the write-only handle is
    /// what lets finalization decide the outcome by looking at one accumulator (FR-124).
    ///
    /// This function no longer builds a verdict. It builds a plan, runs detectors, and hands the evidence
    /// to [`crate::finalize`] — which is the only producer (FR-120). 001 assembled verdicts here in three
    /// places, sorted reasons here as well as in `assemble`, and kept six overlapping collections whose
    /// mutual agreement the score depended on.
    pub fn scan(&self, input: &[u8], policy: &ScanPolicy, target: TargetRef) -> Verdict {
        let plan = ScanPlan::resolve(policy, self.ruleset.all_rules());
        let bounds = plan.bounds();
        let mut evidence = Evidence::new();

        // ── Size gate ───────────────────────────────────────────────────────────────────────────
        //
        // First, and short-circuiting: an oversized input is not analysed at all, so there is nothing to
        // report except that fact. Routed through finalization rather than assembling a verdict here
        // (T018), which is why this branch no longer has to know that `score: 0` and `risk: None` are the
        // right values for a verdict with no findings.
        if input.len() as u64 > bounds.max_input_bytes {
            return finalize::oversized(
                bounds.max_input_bytes,
                input.len(),
                target,
                self.ruleset.id().clone(),
            );
        }

        // ── Structure ───────────────────────────────────────────────────────────────────────────
        //
        // Classify quoting regions once, before any matching, so every rule-driven observation can be
        // checked against it without re-deriving the map.
        let quoting = QuotingMap::build(input);

        // ── Decode ──────────────────────────────────────────────────────────────────────────────
        //
        // Recovered texts are re-scanned against the same rules. A transformation is reported only when
        // its decoded content trips a rule, which is what keeps "contains base-64" from being a finding.
        //
        // The decoder records its own bounds now (T021). This call site used to translate two booleans
        // into coverage judgements, and one of the translations was the bug that made every scan
        // inconclusive.
        let expansion = decode::expand(input, bounds.max_decode_depth, &mut evidence);

        // ── Prefilter ───────────────────────────────────────────────────────────────────────────
        //
        // One linear pass to learn which rules are worth compiling. Text matching no literal — nearly all
        // text — leaves this loop having compiled nothing.
        let rules = plan.rules();
        let candidates = self.prefilter.candidates(input);

        // ── Patterns ────────────────────────────────────────────────────────────────────────────
        let mut hits: Vec<Observation> = Vec::new();

        for index in candidates {
            let rule = &rules[index];
            if !plan.is_active(rule.class) {
                continue;
            }

            // Saturation and uncompilable patterns are recorded by the matcher itself (T022), so there is
            // no longer an `Err` here for this loop to interpret.
            for span in self.patterns.matches(
                index,
                rule,
                input,
                bounds.max_matches_per_rule,
                &mut evidence,
            ) {
                let (matched, _) = sanitize_bytes(
                    &input[span.start..span.end],
                    bounds.max_excerpt_bytes as usize,
                );
                hits.push(Observation {
                    rule_id: rule.id.clone(),
                    class: rule.class,
                    span,
                    matched,
                    severity: rule.severity,
                    description: rule.description.clone(),
                    chain: Vec::new(),
                });
            }
        }

        // ── Rules against decoded content ───────────────────────────────────────────────────────
        //
        // Collected separately because these are deliberately EXEMPT from quoting suppression. Suppression
        // exists to excuse text that is quoting a payload rather than issuing one — but someone who
        // base-64'd an instruction was not illustrating it. The obfuscation is itself the evidence of
        // intent, and "it appeared after the words 'for example'" is not exculpatory for content that had
        // to be decoded before it could be read.
        //
        // This also removes a whole class of trivial evasion: wrapping an encoded payload in a code fence.
        //
        // Each recovered text is matched against the same rules. An observation reports the span of the
        // *encoded* region in the original input — bytes the caller actually holds — and carries the
        // transform chain, so the reader sees both where it was and how it was hidden.
        let mut decoded_hits: Vec<Observation> = Vec::new();
        for candidate in &expansion.candidates {
            let bytes = candidate.text.as_bytes();
            for index in self.prefilter.candidates(bytes) {
                let rule = &rules[index];
                if !plan.is_active(rule.class) {
                    continue;
                }
                let spans = self.patterns.matches(
                    index,
                    rule,
                    bytes,
                    bounds.max_matches_per_rule,
                    &mut evidence,
                );
                if spans.is_empty() {
                    continue;
                }
                // One observation per rule per candidate, not one per match. A payload repeated inside a
                // decoded blob is still one concealed payload, and reporting each occurrence would let a
                // single encoded region fill the reason budget.
                let (excerpt, _) = crate::sanitize::sanitize_str(
                    &candidate.text,
                    bounds.max_excerpt_bytes as usize,
                );
                decoded_hits.push(Observation {
                    rule_id: rule.id.clone(),
                    // Still relabelled from the rule's own class, which is the US2 defect: this
                    // observation had to satisfy the class filter above as its rule's class and then
                    // arrived carrying another. T050 makes it carry `rule.class`; changing it here would
                    // be a behaviour change, and Phase 2 is not where behaviour changes.
                    class: DetectionClass::Encoding,
                    span: candidate.origin,
                    matched: excerpt,
                    severity: rule.severity,
                    description: format!("{} Recovered by decoding.", rule.description),
                    chain: candidate.chain.clone(),
                });
            }
        }

        // ── Suppression ─────────────────────────────────────────────────────────────────────────
        //
        // Rule-driven observations only. A documentation example of an override phrase is prose; a
        // document that actually contains invisible characters is smuggling them regardless of the
        // surrounding text.
        let (mut kept, suppressed) = if plan.suppress_in_quotes() {
            detect::apply_suppression(hits, &quoting, |rule_id| {
                rules
                    .iter()
                    .find(|r| r.id == rule_id)
                    .map(|r| r.fires_in_quotes)
                    .unwrap_or(false)
            })
        } else {
            (hits, Vec::new())
        };

        // Suppressed observations are dropped rather than retained. That is the state US4 changes: FR-128
        // wants them recorded with the context that suppressed them, because suppression is the main lever
        // on the false-positive problem and its effect currently cannot be measured from one run. T066 and
        // T067 replace this discard.
        let _ = suppressed;

        // ── Structural and decoded detectors ────────────────────────────────────────────────────
        //
        // Added after suppression because none of these are suppressed. Concealment and confusables detect
        // a mechanism rather than a phrase, and decoded content carries its own evidence of intent.
        for hit in detect::structural::scan(input) {
            if plan.is_active(hit.class) {
                kept.push(hit);
            }
        }
        for hit in decoded_hits {
            if plan.is_active(hit.class) {
                kept.push(hit);
            }
        }

        // ── Score, then hand over ───────────────────────────────────────────────────────────────
        //
        // The score is aggregated over EVERY observation, before finalization orders and truncates the
        // reasons (FR-001b): reasons are ordered by byte offset rather than by severity, so truncating
        // first could discard the highest-severity finding and understate the score.
        //
        // This is the parallel collection FR-124 exists to remove. It survives Phase 2 because deriving
        // the score inside finalization is T058's job and has a test that must go red first — but note
        // that it is now derived from the same `kept` list that becomes the observations, in one pass,
        // rather than from a separately-accumulated `all_hits` as in 001.
        let severities: Vec<(u8, DetectionClass)> =
            kept.iter().map(|hit| (hit.severity, hit.class)).collect();
        let score = aggregate(&severities);
        let risk = self.ruleset.bands().band(score);

        for hit in kept {
            evidence.observe(hit);
        }

        finalize::finalize(
            evidence,
            bounds,
            Attribution {
                score,
                risk,
                target,
                ruleset: self.ruleset.id().clone(),
            },
        )
    }

    /// The resource limits this engine enforces when compiling patterns.
    pub fn limits(&self) -> &RulesetLimits {
        &self.limits
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
        Ok(Engine::from_ruleset(ruleset, self.limits))
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
