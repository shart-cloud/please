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
use crate::detect::{self, pattern::PatternSet, Hit};
use crate::policy::ScanPolicy;
use crate::prefilter::Prefilter;
use crate::ruleset::{Ruleset, RulesetError, RulesetLimits};
use crate::sanitize::sanitize_bytes;
use crate::score::aggregate;
use crate::structure::QuotingMap;
use crate::verdict::{
    DetectionClass, EngineId, IncompleteCause, Incompleteness, Reason, RulesetId, TargetRef,
    Verdict, VerdictParts,
};

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
    /// size gate → [decode] → [structure] → prefilter → patterns → [suppression] → score → verdict
    /// ```
    ///
    /// Stages in brackets arrive with User Story 1 (T044–T056): bounded decoding, the quoting pre-pass,
    /// and the concealment and confusable detectors. The stages present now are the ones every other
    /// stage plugs into, and the accumulate-then-assemble shape is what makes the FR-004 invariant
    /// checkable at a single point.
    ///
    /// Every stage may only *add* reasons or record coverage gaps; none may remove them. That
    /// monotonicity is why assembly can decide the outcome by looking at two accumulators.
    pub fn scan(&self, input: &[u8], policy: &ScanPolicy, target: TargetRef) -> Verdict {
        let mut reasons: Vec<Reason> = Vec::new();
        let mut incomplete: Vec<Incompleteness> = Vec::new();

        // ── Size gate ───────────────────────────────────────────────────────────────────────────
        //
        // First, and short-circuiting. An oversized input is not analysed at all, so there is nothing
        // to report except that fact — and reporting it as clean would be the exact fail-open the
        // whole outcome model exists to prevent (FR-017).
        if input.len() as u64 > policy.max_input_bytes {
            return Verdict::assemble(VerdictParts {
                score: 0,
                risk: crate::verdict::RiskLevel::None,
                reasons,
                reasons_truncated: false,
                incomplete: vec![Incompleteness::bound(
                    IncompleteCause::InputSize,
                    policy.max_input_bytes,
                )
                .with_detail(format!("input is {} bytes", input.len()))],
                target,
                ruleset: self.ruleset.id().clone(),
                engine: EngineId::current(),
            });
        }

        // ── Structure ───────────────────────────────────────────────────────────────────────────
        //
        // Classify quoting regions once, before any matching, so every rule-driven hit can be checked
        // against it without re-deriving the map.
        let quoting = QuotingMap::build(input);

        // ── Decode ──────────────────────────────────────────────────────────────────────────────
        //
        // Recovered texts are re-scanned against the same rules. A transformation is reported only when
        // its decoded content trips a rule, which is what keeps "contains base-64" from being a finding.
        let expansion = decode::expand(input, policy.max_decode_depth);
        if expansion.depth_exceeded {
            incomplete.push(
                Incompleteness::bound(IncompleteCause::DecodeDepth, policy.max_decode_depth as u64)
                    .with_detail(
                        "nested encoding beyond the depth bound was not examined".to_string(),
                    ),
            );
        }
        if expansion.fanout_exceeded {
            incomplete.push(Incompleteness::failure(
                IncompleteCause::DecodeFailed,
                "too many decodable regions; some were not examined",
            ));
        }

        // ── Prefilter ───────────────────────────────────────────────────────────────────────────
        //
        // One linear pass to learn which rules are worth compiling. Text matching no literal — nearly
        // all text — leaves this loop having compiled nothing.
        let rules = self.ruleset.all_rules();
        let candidates = self.prefilter.candidates(input);

        // ── Patterns ────────────────────────────────────────────────────────────────────────────
        //
        // `all_hits` feeds scoring and is NOT truncated; `reasons` is what gets reported and is. That
        // split is FR-001b: reasons are ordered by offset rather than severity, so truncating before
        // aggregating could discard the highest-severity finding and understate the score.
        let mut all_hits: Vec<(u8, DetectionClass)> = Vec::new();
        let mut saturated_rules: Vec<String> = Vec::new();
        let mut hits: Vec<Hit> = Vec::new();

        for index in candidates {
            let rule = &rules[index];
            if !policy.is_active(rule.class) {
                continue;
            }

            match self
                .patterns
                .matches(index, rule, input, policy.max_matches_per_rule)
            {
                Ok(found) => {
                    if found.saturated {
                        saturated_rules.push(rule.id.clone());
                    }
                    for span in found.spans {
                        let (matched, _) = sanitize_bytes(
                            &input[span.start..span.end],
                            policy.max_excerpt_bytes as usize,
                        );
                        hits.push(Hit {
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
                // A rule that will not compile is a gap in coverage, not a rule that found nothing.
                // Unreachable for a rule set that passed `validate_compiled`, and recorded rather than
                // ignored precisely because "unreachable" is not "impossible".
                Err(unavailable) => incomplete.push(
                    Incompleteness::failure(
                        IncompleteCause::RulesetUnavailable,
                        unavailable.detail,
                    )
                    .with_detail(format!(
                        "rule `{}` could not be compiled",
                        unavailable.rule_id
                    )),
                ),
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
        let mut decoded_hits: Vec<Hit> = Vec::new();

        //
        // Each recovered text is matched against the same rules. A hit reports the span of the *encoded*
        // region in the original input — bytes the caller actually holds — and carries the transform
        // chain, so the reader sees both where it was and how it was hidden.
        for candidate in &expansion.candidates {
            let bytes = candidate.text.as_bytes();
            for index in self.prefilter.candidates(bytes) {
                let rule = &rules[index];
                if !policy.is_active(rule.class) {
                    continue;
                }
                if let Ok(found) =
                    self.patterns
                        .matches(index, rule, bytes, policy.max_matches_per_rule)
                {
                    if found.spans.is_empty() {
                        continue;
                    }
                    // One hit per rule per candidate, not one per match. A payload repeated inside a
                    // decoded blob is still one concealed payload, and reporting each occurrence would
                    // let a single encoded region fill the reason budget.
                    let (excerpt, _) = crate::sanitize::sanitize_str(
                        &candidate.text,
                        policy.max_excerpt_bytes as usize,
                    );
                    decoded_hits.push(Hit {
                        rule_id: rule.id.clone(),
                        class: DetectionClass::Encoding,
                        span: candidate.origin,
                        matched: excerpt,
                        severity: rule.severity,
                        description: format!("{} Recovered by decoding.", rule.description),
                        chain: candidate.chain.clone(),
                    });
                }
            }
        }

        // ── Suppression ─────────────────────────────────────────────────────────────────────────
        //
        // Rule-driven hits only. A documentation example of an override phrase is prose; a document that
        // actually contains invisible characters is smuggling them regardless of the surrounding text.
        let (mut kept, suppressed) = if policy.suppress_in_quotes {
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

        // Suppressed hits are dropped rather than reported. `--no-suppress-in-quotes` works by not
        // suppressing in the first place (the branch above), which is simpler than reporting-with-a-flag
        // and gives the caller exactly one thing to reason about.
        let _ = suppressed;

        // ── Structural and decoded detectors ────────────────────────────────────────────────────
        //
        // Added after suppression because none of these are suppressed. Concealment and confusables detect
        // a mechanism rather than a phrase, and decoded content carries its own evidence of intent.
        for hit in detect::structural::scan(input) {
            if policy.is_active(hit.class) {
                kept.push(hit);
            }
        }
        for hit in decoded_hits {
            if policy.is_active(hit.class) {
                kept.push(hit);
            }
        }

        // ── Assemble reasons ────────────────────────────────────────────────────────────────────
        for hit in kept {
            all_hits.push((hit.severity, hit.class));
            let (reason, excerpt_truncated) = hit.into_reason(policy.max_excerpt_bytes as usize);
            if excerpt_truncated {
                incomplete.push(
                    Incompleteness::bound(
                        IncompleteCause::ExcerptLength,
                        policy.max_excerpt_bytes as u64,
                    )
                    .with_detail(format!("excerpt for `{}` truncated", reason.rule_id)),
                );
            }
            reasons.push(reason);
        }

        if !saturated_rules.is_empty() {
            incomplete.push(
                Incompleteness::bound(
                    IncompleteCause::MaxMatchesPerRule,
                    policy.max_matches_per_rule as u64,
                )
                .with_detail(format!("saturated: {}", saturated_rules.join(", "))),
            );
        }

        // ── Score, then truncate ────────────────────────────────────────────────────────────────
        let score = aggregate(&all_hits);
        let risk = self.ruleset.bands().band(score);

        let mut reasons_truncated = false;
        if reasons.len() > policy.max_reasons as usize {
            reasons_truncated = true;
            incomplete.push(
                Incompleteness::bound(IncompleteCause::MaxReasons, policy.max_reasons as u64)
                    .with_detail(format!("{} reasons found", reasons.len())),
            );
            // Sort before truncating so the reasons kept are the earliest in the input rather than
            // whichever the rule iteration order happened to produce (SC-011).
            reasons.sort_by(|a, b| {
                a.span
                    .start
                    .cmp(&b.span.start)
                    .then_with(|| a.rule_id.cmp(&b.rule_id))
            });
            reasons.truncate(policy.max_reasons as usize);
        }

        Verdict::assemble(VerdictParts {
            score,
            risk,
            reasons,
            reasons_truncated,
            incomplete,
            target,
            ruleset: self.ruleset.id().clone(),
            engine: EngineId::current(),
        })
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
