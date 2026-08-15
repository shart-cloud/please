//! The verdict model — what a scan returns, and the invariant it may never break.
//!
//! The single most important property in this crate lives here: a [`Verdict`] whose outcome is
//! [`Outcome::Clean`] guarantees that the whole input was examined and nothing was found. Analysis
//! that ran out of budget, hit an unreadable target, or lost a decoder is [`Outcome::Inconclusive`],
//! never clean (FR-004, SC-007).
//!
//! That guarantee is enforced structurally rather than by convention. [`Verdict`]'s fields are private
//! and its only constructor is [`Verdict::assemble`], so there is no way for a caller — or for a
//! future detector in this crate — to hand back a clean verdict alongside a recorded gap in coverage.
//! A rule you can bypass by writing a struct literal is not an invariant, it is a suggestion.

use crate::policy::ScanPolicy;

/// A half-open byte range into the **original** input.
///
/// Always original coordinates, even for matches recovered by decoding: a caller highlighting a
/// finding has to be able to point at bytes the user actually holds. Where a match came out of
/// decoded content, the position within that content lives in [`Transform::input_span`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    pub fn new(start: usize, end: usize) -> Self {
        debug_assert!(start <= end, "span start must not exceed end");
        Self { start, end }
    }

    pub fn len(&self) -> usize {
        self.end.saturating_sub(self.start)
    }

    pub fn is_empty(&self) -> bool {
        self.start >= self.end
    }
}

/// The human-facing risk band, derived from the score by the rule set's band table.
///
/// Ordered so a threshold comparison is a comparison. Band boundaries are **provisional** until the
/// evaluation harness calibrates them against per-source corpus metrics; see `docs/limits.md`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Critical,
}

/// A named family of related payload techniques (FR-015).
///
/// `non_exhaustive` from the outset: the set of things an attacker does grows, and adding the seventh
/// class should not break every embedder's `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DetectionClass {
    /// Instructions to disregard, replace, or supersede prior instructions (FR-008).
    Override,
    /// Text hidden by invisible, zero-width, bidi, tag-block, or variation-selector characters (FR-009).
    Concealment,
    /// Characters chosen to resemble others, evaluated per token (FR-010).
    Confusable,
    /// Payloads recovered by bounded decoding (FR-011).
    Encoding,
    /// Forged role markers, system-instruction or tool-result impersonation (FR-012).
    Boundary,
    /// Requests for an agent's instructions, configuration, or credentials (FR-013).
    Solicitation,
}

impl DetectionClass {
    /// Stable wire name. Kept beside the variants so the serialised form cannot drift from them.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Override => "override",
            Self::Concealment => "concealment",
            Self::Confusable => "confusable",
            Self::Encoding => "encoding",
            Self::Boundary => "boundary",
            Self::Solicitation => "solicitation",
        }
    }
}

/// The three-way result (FR-003).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Analysis completed and found nothing. Requires that nothing was left unexamined.
    Clean,
    /// At least one rule fired.
    RiskFound,
    /// Analysis did not complete. Carries its causes in [`Verdict::incomplete`].
    Inconclusive,
}

impl Outcome {
    /// Precedence rank for deriving a summary from several verdicts (FR-032b).
    ///
    /// `RiskFound` > `Inconclusive` > `Clean`. Ranking `Clean` above `Inconclusive` would be the
    /// FR-004 fail-open one level up: a directory reported safe on the strength of files nobody read.
    pub fn rank(&self) -> u8 {
        match self {
            Self::Clean => 0,
            Self::Inconclusive => 1,
            Self::RiskFound => 2,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Clean => "clean",
            Self::RiskFound => "risk_found",
            Self::Inconclusive => "inconclusive",
        }
    }
}

/// A quoting region that suppresses a match by default (FR-014, research D8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum QuotingContext {
    FencedCode,
    InlineCode,
    BlockQuote,
    QuotedString,
    AttributiveMarker,
}

/// One transformation recognised while decoding (FR-011).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TransformKind {
    Base64,
    Hex,
    Rot13,
    Reversed,
    Leetspeak,
    /// Unicode Tags block, U+E0000–U+E007F — the current state of the art in invisible payloads.
    UnicodeTags,
    /// Variation selectors, used to smuggle arbitrary bytes.
    VariationSelectors,
}

/// One link in a decoding chain.
///
/// Never appears alone: a `Transform` exists only inside a [`Reason`] whose rule fired on decoded
/// content. That is the structural expression of the rule that an encoding is not itself a finding —
/// "this file contains base64" describes most config files and every certificate, and reporting it
/// would produce exactly the false-positive flood that gets a scanner switched off (research D5).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transform {
    pub kind: TransformKind,
    pub depth: u8,
    pub input_span: Span,
    pub decoded_excerpt: String,
}

/// One supporting observation within a verdict (FR-002).
///
/// A verdict without these is an assertion; with them it is evidence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    /// Namespaced rule identifier, e.g. `override.ignore_previous`. Also the suppression handle.
    pub rule_id: String,
    pub class: DetectionClass,
    pub span: Span,
    /// Excerpt of the matching content, **already neutralised** (FR-021).
    ///
    /// Sanitised at this boundary rather than at each display site, so the guarantee holds for every
    /// consumer including the ones that forget. Sanitise the payload, then style it — never the
    /// reverse.
    pub matched: String,
    pub severity: u8,
    /// Empty for a direct match; populated when the match came out of decoded content.
    pub chain: Vec<Transform>,
    /// Why this rule exists, carried from the rule so a finding explains itself without a lookup.
    pub description: String,
    /// Present only when a quoting context would normally have suppressed this reason and
    /// suppression was disabled by policy.
    pub suppressed_by: Option<QuotingContext>,
}

/// Why some part of the input went unexamined (FR-003, FR-007, FR-017, FR-018, FR-032a).
///
/// Divided into bounds the caller configured and can raise, and failures in the environment that have
/// to be fixed. The distinction is what a caller *does about it*, and it is carried in the enum rather
/// than in two separate lists — one list keeps the [`Outcome::Clean`] invariant a check on a single
/// field, and a second accumulator would be a second place to forget it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IncompleteCause {
    // ── Bounds: a limit the caller set ──────────────────────────────────────────────────────────
    InputSize,
    DecodeDepth,
    MaxMatchesPerRule,
    MaxReasons,
    ExcerptLength,

    // ── Failures: something the environment did ─────────────────────────────────────────────────
    /// A target could not be read. During a directory walk the walk continues and this target is
    /// inconclusive — never silently skipped (FR-032a).
    TargetUnreadable,
    DecodeFailed,
    RulesetUnavailable,
    /// An optional detection tier was unavailable, which degrades to inconclusive and never to clean.
    TierUnavailable,
}

impl IncompleteCause {
    /// True for a configured bound, false for an environmental failure.
    pub fn is_bound(&self) -> bool {
        matches!(
            self,
            Self::InputSize
                | Self::DecodeDepth
                | Self::MaxMatchesPerRule
                | Self::MaxReasons
                | Self::ExcerptLength
        )
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::InputSize => "input_size",
            Self::DecodeDepth => "decode_depth",
            Self::MaxMatchesPerRule => "max_matches_per_rule",
            Self::MaxReasons => "max_reasons",
            Self::ExcerptLength => "excerpt_length",
            Self::TargetUnreadable => "target_unreadable",
            Self::DecodeFailed => "decode_failed",
            Self::RulesetUnavailable => "ruleset_unavailable",
            Self::TierUnavailable => "tier_unavailable",
        }
    }
}

/// One thing the scan did not examine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incompleteness {
    pub cause: IncompleteCause,
    /// The value in force when a bound was reached, so a caller can raise it deliberately. Present
    /// for bounds, absent for failures.
    pub configured: Option<u64>,
    /// What went unexamined — which rule saturated, which region was skipped, why a target could not
    /// be read.
    pub detail: Option<String>,
}

impl Incompleteness {
    /// A bound that was reached, with the configured value that stopped analysis.
    pub fn bound(cause: IncompleteCause, configured: u64) -> Self {
        debug_assert!(cause.is_bound(), "{cause:?} is not a bound");
        Self {
            cause,
            configured: Some(configured),
            detail: None,
        }
    }

    /// An environmental failure, with a human-readable explanation.
    pub fn failure(cause: IncompleteCause, detail: impl Into<String>) -> Self {
        debug_assert!(!cause.is_bound(), "{cause:?} is a bound, not a failure");
        Self {
            cause,
            configured: None,
            detail: Some(detail.into()),
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

/// What kind of thing was scanned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetKind {
    Path,
    Stdin,
    Buffer,
}

/// What was scanned — reporting metadata only.
///
/// Explicitly never an input to judgement (FR-020): a file's name or path can never influence its own
/// verdict. `name` is the path **as given**, never absolutised, so output does not vary with the
/// working directory it was produced from (SC-011).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRef {
    pub kind: TargetKind,
    pub name: Option<String>,
    pub bytes: usize,
}

impl TargetRef {
    pub fn path(name: impl Into<String>, bytes: usize) -> Self {
        Self {
            kind: TargetKind::Path,
            name: Some(name.into()),
            bytes,
        }
    }

    pub fn stdin(bytes: usize) -> Self {
        Self {
            kind: TargetKind::Stdin,
            name: None,
            bytes,
        }
    }

    pub fn buffer(name: impl Into<String>, bytes: usize) -> Self {
        Self {
            kind: TargetKind::Buffer,
            name: Some(name.into()),
            bytes,
        }
    }
}

/// Identity of the resolved rule set (FR-005).
///
/// The `digest` covers every rule that survived resolution, so two verdicts carrying the same values
/// really were produced by the same rules — which is what makes an old verdict attributable (SC-012).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RulesetId {
    pub name: String,
    pub version: String,
    pub digest: String,
}

/// Identity of the engine that produced a verdict (FR-005).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineId {
    pub name: String,
    pub version: String,
}

impl EngineId {
    /// This build's identity, read from package metadata so there is no second place to update.
    pub fn current() -> Self {
        Self {
            name: crate::ENGINE_NAME.to_string(),
            version: crate::ENGINE_VERSION.to_string(),
        }
    }
}

/// The inputs to [`Verdict::assemble`].
///
/// A struct rather than eight positional parameters: the fields are easy to transpose and a
/// transposed `score`/`severity` pair would be a silent scoring bug rather than a compile error.
#[derive(Debug, Clone)]
pub struct VerdictParts {
    /// Aggregate score, computed over **every** match found before truncation (FR-001b).
    pub score: u8,
    pub risk: RiskLevel,
    pub reasons: Vec<Reason>,
    pub reasons_truncated: bool,
    pub incomplete: Vec<Incompleteness>,
    pub target: TargetRef,
    pub ruleset: RulesetId,
    pub engine: EngineId,
}

/// The complete result of one scan.
///
/// Fields are private on purpose. [`Verdict::assemble`] is the only constructor, which makes it the
/// single place the [`Outcome::Clean`] invariant is decided — see the module documentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    outcome: Outcome,
    score: u8,
    risk: RiskLevel,
    reasons: Vec<Reason>,
    reasons_truncated: bool,
    incomplete: Vec<Incompleteness>,
    target: TargetRef,
    ruleset: RulesetId,
    engine: EngineId,
}

impl Verdict {
    /// Derive the outcome from the evidence and build the verdict.
    ///
    /// **This is the single point where the [`Outcome::Clean`] invariant is decided** (FR-004,
    /// FR-032b). Every other path into a `Verdict` goes through here, which is the entire reason the
    /// fields are private.
    ///
    /// The order of the three branches is the design:
    ///
    /// 1. Any reason at all makes this `RiskFound`, **even if coverage was also incomplete**. A scan
    ///    that found a real payload and then ran out of budget has still found a real payload;
    ///    downgrading it to inconclusive would discard a confirmed detection. The gap stays visible in
    ///    [`Verdict::incomplete`] so the caller knows the finding may not be the only one.
    /// 2. Otherwise, anything left unexamined makes this `Inconclusive`. "Found nothing" and "looked
    ///    at nothing" are indistinguishable from the outside, so they must not collapse into the same
    ///    outcome.
    /// 3. Only with both empty is the verdict `Clean`.
    pub fn assemble(parts: VerdictParts) -> Self {
        let VerdictParts {
            score,
            risk,
            mut reasons,
            reasons_truncated,
            incomplete,
            target,
            ruleset,
            engine,
        } = parts;

        let outcome = if !reasons.is_empty() {
            Outcome::RiskFound
        } else if !incomplete.is_empty() {
            Outcome::Inconclusive
        } else {
            Outcome::Clean
        };

        // A verdict with no reasons has nothing for a score to summarise, so any score handed in is
        // discarded rather than reported. Trusting the caller here would let a scoring bug surface as
        // a confusing "clean, score 42" verdict instead of as a failing test.
        let (score, risk) = match outcome {
            Outcome::Clean | Outcome::Inconclusive => (0, RiskLevel::None),
            Outcome::RiskFound => (score, risk),
        };

        // Total order over reasons: byte offset, then rule id as the tie-break. Deterministic output
        // is a requirement rather than a nicety (FR-030, SC-011) — it is what lets a caller cache a
        // verdict and diff it in CI. Sorting by *offset* rather than by severity is also why the score
        // must be aggregated before truncation (FR-001b): truncating an offset-ordered list can drop
        // the highest-severity finding.
        reasons.sort_by(|a, b| {
            a.span
                .start
                .cmp(&b.span.start)
                .then_with(|| a.rule_id.cmp(&b.rule_id))
        });

        Self {
            outcome,
            score,
            risk,
            reasons,
            reasons_truncated,
            incomplete,
            target,
            ruleset,
            engine,
        }
    }

    pub fn outcome(&self) -> Outcome {
        self.outcome
    }

    pub fn score(&self) -> u8 {
        self.score
    }

    pub fn risk(&self) -> RiskLevel {
        self.risk
    }

    pub fn reasons(&self) -> &[Reason] {
        &self.reasons
    }

    pub fn reasons_truncated(&self) -> bool {
        self.reasons_truncated
    }

    pub fn incomplete(&self) -> &[Incompleteness] {
        &self.incomplete
    }

    pub fn target(&self) -> &TargetRef {
        &self.target
    }

    pub fn ruleset(&self) -> &RulesetId {
        &self.ruleset
    }

    pub fn engine(&self) -> &EngineId {
        &self.engine
    }

    /// True when this verdict's risk meets or exceeds `threshold`.
    ///
    /// Note what this does **not** do: it does not decide anything. Whether a verdict at or above a
    /// threshold blocks, warns, or is logged is the caller's policy (FR-006, Principle I).
    pub fn is_at_or_above(&self, threshold: RiskLevel) -> bool {
        self.risk >= threshold
    }

    /// True when the caller should treat this scan's coverage as partial.
    pub fn is_incomplete(&self) -> bool {
        !self.incomplete.is_empty()
    }

    /// A verdict for a target that could not be read (FR-032a).
    ///
    /// Lives here rather than in the CLI because the core never opens a file, so the *caller* doing
    /// the I/O has to produce this — and it must be trivial to produce correctly. Skipping the file
    /// instead is the one thing that must not happen.
    pub fn unreadable_target(
        target: TargetRef,
        detail: impl Into<String>,
        ruleset: RulesetId,
    ) -> Self {
        Self::assemble(VerdictParts {
            score: 0,
            risk: RiskLevel::None,
            reasons: Vec::new(),
            reasons_truncated: false,
            incomplete: vec![Incompleteness::failure(
                IncompleteCause::TargetUnreadable,
                detail,
            )],
            target,
            ruleset,
            engine: EngineId::current(),
        })
    }
}

/// Reserved for the scan pipeline (T032); referenced here so the policy module is wired in.
#[allow(dead_code)]
fn _policy_is_reachable(_: &ScanPolicy) {}
