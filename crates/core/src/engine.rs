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
use crate::detect;
use crate::finalize::evidence::{Evidence, Observation};
use crate::finalize::plan::ScanPlan;
use crate::finalize::types::{RulesetId, TargetRef, Verdict};
use crate::finalize::{self, Attribution};
use crate::matcher::Matcher;
use crate::policy::ScanPolicy;
use crate::prepare::{self, PreparedRuleset};
use crate::ruleset::{Bands, Ruleset, RulesetError, RulesetLimits};
use crate::sanitize::sanitize_bytes;
use crate::structure::QuotingMap;

/// A compiled rule set, ready to scan.
///
/// `Send + Sync`, so one engine serves concurrent scans. Deliberately **not** `Clone`: it holds a
/// memoisation cache of compiled patterns, and cloning would silently discard the work and re-pay
/// compilation on the copy. Share it behind an `Arc` instead — which is what a harness holding one
/// engine for the process wants anyway.
#[derive(Debug)]
pub struct Engine {
    /// Rules, the literal prefilter, and the compiled patterns, as one thing (T074, FR-140).
    ///
    /// 001 held all three here as separate fields and coordinated them by rule position. That coordination
    /// was the coupling US5 removes: the engine no longer knows a rule has a position.
    matcher: Matcher,
    /// Identity covering content, provenance, and validation state (FR-111). Distinct from
    /// `ruleset.id()`, which covers content alone, and this is the one reported in every verdict — so a
    /// verdict can tell an auditor whether caller-supplied rules were involved.
    id: RulesetId,
    limits: RulesetLimits,
    bands: Bands,
}

impl Engine {
    /// Build a scanner from a prepared rule set. **The only constructor** (FR-102, FR-103).
    ///
    /// Infallible, and that is the point: everything that could fail happened during preparation, so
    /// holding a [`PreparedRuleset`] *is* the proof. There is no path from rule text to a scanner that does
    /// not pass through validation, and therefore no call order for a caller to get wrong.
    ///
    /// 001 had `from_ruleset(Ruleset, RulesetLimits)`, which accepted anything that had parsed. Compiled
    /// validation was a separate public method a caller was asked to remember, and no caller did.
    pub fn prepared(prepared: PreparedRuleset) -> Self {
        let (ruleset, id, retained, limits) = prepared.into_parts();
        let bands = *ruleset.bands();
        // The compiled patterns validation already paid for, carried straight into the matcher rather than
        // discarded and re-derived on first match (FR-109, SC-106).
        let matcher = Matcher::build(ruleset, retained, limits.clone());
        Self {
            matcher,
            id,
            limits,
            bands,
        }
    }

    /// The built-in rule set.
    ///
    /// Returns `Err` only if the embedded rule set is itself invalid, which is a build-time defect rather
    /// than a runtime condition — hence the CI check that establishes it (FR-106).
    pub fn builtin() -> Result<Self, RulesetError> {
        Ok(Self::prepared(prepare::builtin()?))
    }

    /// A rule set from TOML source, replacing the built-in entirely.
    ///
    /// **Every rule is validated, including disabled ones.** This is a behaviour change from 001, where
    /// loading ran only the cheap syntax tier and a counted-repetition size bomb was accepted — the caller
    /// was expected to call `Ruleset::validate_compiled` afterwards, and none did. A rule set that used to
    /// load and now returns `PatternTooComplex` was never safe to scan with.
    pub fn from_toml(source: &str) -> Result<Self, RulesetError> {
        Ok(Self::prepared(prepare::from_source(
            source,
            RulesetLimits::default(),
        )?))
    }

    /// Start from the built-in set and layer caller additions and suppressions on top.
    pub fn builder() -> EngineBuilder {
        EngineBuilder::default()
    }

    pub fn ruleset(&self) -> &Ruleset {
        self.matcher.ruleset()
    }

    /// Identity of the prepared rule set, recorded in every verdict (FR-005, FR-111, SC-012).
    ///
    /// Covers provenance and validation state as well as content, so two engines built from identical rules
    /// — one embedded, one handed in by a caller — report different identities. That is the difference an
    /// auditor needs when someone disputes a finding.
    pub fn ruleset_id(&self) -> &RulesetId {
        &self.id
    }

    /// Whether a rule's pattern is compiled. Test and diagnostic use.
    ///
    /// Exposed because "was this compiled twice?" is the claim SC-106 makes and there is no way to observe
    /// it from the outside otherwise. Answers `false` for an unknown id, which is the honest answer: an
    /// absent rule has no compiled pattern.
    pub fn pattern_is_compiled(&self, rule_id: &str) -> bool {
        self.matcher.pattern_is_compiled(rule_id)
    }

    /// Non-fatal observations from loading — a rule with no literal gate, a built-in replaced by an
    /// addition. Surfaced so overriding a rule is never accidental.
    pub fn warnings(&self) -> &[String] {
        self.matcher.ruleset().warnings()
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
        let plan = ScanPlan::resolve(policy);
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
                self.id.clone(),
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

        // ── Match ───────────────────────────────────────────────────────────────────────────────
        //
        // Two matching passes, each extracted below so this function reads as the sequence of stages it is
        // rather than as the stages themselves (T061).
        let direct = self.observe_matches(
            input,
            bounds.max_matches_per_rule,
            bounds.max_excerpt_bytes,
            &mut evidence,
        );
        let decoded = self.observe_decoded(&plan, &expansion, &mut evidence);

        // ── Suppression ─────────────────────────────────────────────────────────────────────────
        //
        // Rule-driven observations from the original input only. A documentation example of an override
        // phrase is prose; a document that actually contains invisible characters is smuggling them
        // regardless of the surrounding text.
        //
        // Decoded observations are deliberately EXEMPT. Suppression excuses text that is quoting a payload
        // rather than issuing one, and someone who base-64'd an instruction was not illustrating it — the
        // obfuscation is itself the evidence of intent. It also removes a whole class of trivial evasion:
        // wrapping an encoded payload in a code fence.
        let (mut kept, quoted) = detect::apply_suppression(direct, &quoting, |rule_id| {
            // Asked by id. 001 looked this up over a slice the plan handed the engine, which meant the
            // rule slice had two holders.
            self.matcher.fires_in_quotes(rule_id)
        });

        // The quoting context is computed either way, and only the *action* depends on policy (T067).
        //
        // 001 skipped `apply_suppression` entirely when suppression was off, which is why the third US4
        // acceptance scenario was unreachable: with the heuristic disabled there was no context to annotate a
        // reported observation with, so a reader could not tell which findings the heuristic disagreed with
        // them about without running the scan a second time.
        //
        // And when suppression was on, the list was discarded — `let _ = suppressed;`, with a comment noting
        // that dropping was simpler than reporting-with-a-flag. It was. The cost was that the principal lever
        // on the false-positive problem had no observable effect in a single run (FR-128, SC-110).
        if plan.suppress_in_quotes() {
            for (observation, context) in quoted {
                evidence.suppress(observation, context);
            }
        } else {
            kept.extend(quoted.into_iter().map(|(mut observation, context)| {
                observation.suppressed_by = Some(context);
                observation
            }));
        }

        // ── Structural detectors ────────────────────────────────────────────────────────────────
        //
        // Added after suppression because none of these are suppressed. Concealment and confusables detect a
        // mechanism rather than a phrase, and a mechanism is present or it is not.
        kept.extend(detect::structural::scan(input));
        kept.extend(decoded);

        // ── The class filter, applied once ──────────────────────────────────────────────────────
        //
        // **The single application site** (T051, FR-133). Every observation from every source arrives here,
        // each carrying exactly one class, and each is admitted or dropped once.
        //
        // 001 applied this in four places — before matching a rule, before matching a rule against decoded
        // content, and again to each of the structural and decoded observation lists. Four sites is not
        // itself the bug; the bug is that a decoded observation passed through two of them with its class
        // *changed* in between, so `--classes override` failed the second gate and `--classes encoding`
        // failed the first. One site cannot disagree with itself.
        //
        // The cost of moving the gate here rather than keeping it in front of the matcher: a deselected
        // class's patterns may now be compiled before their observations are dropped. That is bounded by the
        // literal prefilter, which already gates compilation on a literal being present, and it buys the
        // property the defect was about. Phase 7's matcher takes ownership of the rule slice and can restore
        // the pre-gate as a view over participating rules — one gate that also filters, rather than two
        // gates that must agree.
        kept.retain(|observation| plan.admits(observation.class));

        // ── Hand over ───────────────────────────────────────────────────────────────────────────
        //
        // No score is computed here (T058). Finalization derives it from the accumulator, which is what
        // removes the second collection whose agreement with the first the score used to depend on.
        for observation in kept {
            evidence.observe(observation);
        }

        finalize::finalize(
            evidence,
            bounds,
            Attribution {
                target,
                ruleset: self.id.clone(),
                bands: self.bands,
            },
        )
    }

    /// Turn every rule match on `haystack` into an observation.
    ///
    /// No index anywhere: the matcher yields a [`RuleMatch`](crate::matcher::RuleMatch) carrying the rule
    /// itself, so everything an observation needs is reachable without knowing where the rule sits (T076,
    /// FR-141).
    fn observe_matches(
        &self,
        haystack: &[u8],
        max_matches: u32,
        max_excerpt: u32,
        evidence: &mut Evidence,
    ) -> Vec<Observation> {
        self.matcher
            .find(haystack, max_matches, evidence)
            .into_iter()
            .map(|found| {
                let (matched, _) = sanitize_bytes(
                    &haystack[found.span.start..found.span.end],
                    max_excerpt as usize,
                );
                Observation {
                    rule_id: found.rule.id.clone(),
                    class: found.rule.class,
                    span: found.span,
                    matched,
                    severity: found.rule.severity,
                    description: found.rule.description.clone(),
                    chain: Vec::new(),
                    suppressed_by: None,
                }
            })
            .collect()
    }

    /// Turn every rule match on recovered text into an observation.
    ///
    /// An observation reports the span of the *encoded* region in the original input — bytes the caller
    /// actually holds — and carries the transform chain, so the reader sees both where it was and how it was
    /// hidden. The excerpt is the recovered text, because that is the thing worth reading.
    ///
    /// One observation per rule per candidate, which is why this asks the matcher for
    /// [`matching_rules`](crate::matcher::Matcher::matching_rules) rather than for every match: a payload
    /// repeated inside a decoded blob is still one concealed payload, and reporting each occurrence would let
    /// a single encoded region fill the reason budget.
    fn observe_decoded(
        &self,
        plan: &ScanPlan<'_>,
        expansion: &decode::Expansion,
        evidence: &mut Evidence,
    ) -> Vec<Observation> {
        let bounds = plan.bounds();
        let mut observations = Vec::new();

        for candidate in &expansion.candidates {
            let bytes = candidate.text.as_bytes();
            let matched_rules =
                self.matcher
                    .matching_rules(bytes, bounds.max_matches_per_rule, evidence);
            if matched_rules.is_empty() {
                continue;
            }
            let (excerpt, _) =
                crate::sanitize::sanitize_str(&candidate.text, bounds.max_excerpt_bytes as usize);
            for rule in matched_rules {
                observations.push(Observation {
                    rule_id: rule.id.clone(),
                    // The class the RULE declares (T050, FR-131). 001 wrote `DetectionClass::Encoding` here,
                    // which is the US2 defect in one line: the observation was gated on the rule's class and
                    // then arrived carrying a different one, so it had to satisfy two filters and no single
                    // selection satisfied both. How it arrived is in `chain`.
                    class: rule.class,
                    span: candidate.origin,
                    matched: excerpt.clone(),
                    severity: rule.severity,
                    description: format!("{} Recovered by decoding.", rule.description),
                    chain: candidate.chain.clone(),
                    suppressed_by: None,
                });
            }
        }

        observations
    }
}

impl Engine {
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

    /// Resolve the layers, validate the caller's rules, and build the engine.
    ///
    /// Delegates to [`crate::prepare::layered`] rather than resolving here (T041). The builder used to
    /// resolve and construct directly, which made it a fourth way into an `Engine` — and the one a caller
    /// reaches for when adding their own rules, so precisely the path that most needed validating and
    /// didn't have it.
    ///
    /// Validation is delta only: an addition costs what its own rules cost, not what the built-in eighty
    /// cost (SC-105).
    pub fn build(self) -> Result<Engine, RulesetError> {
        Ok(Engine::prepared(prepare::layered(
            self.base,
            self.additions,
            &self.suppress,
            self.limits,
        )?))
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
