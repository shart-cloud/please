//! The verdict model — what a scan returns, and the invariant it may never break.
//!
//! The single most important property in this crate lives here: a [`Verdict`] whose outcome is
//! [`Outcome::Clean`] guarantees that the whole input was examined and nothing was found. Analysis
//! that ran out of budget, hit an unreadable target, or lost a decoder is [`Outcome::Inconclusive`],
//! never clean (FR-004, SC-007).
//!
//! That guarantee is enforced structurally rather than by convention. [`Verdict`]'s fields are private and
//! its only constructor is visible only to [`crate::finalize`], so there is no way for a caller — or for a
//! detector in this crate — to hand back a clean verdict alongside a recorded gap in coverage. A rule you
//! can bypass by writing a struct literal is not an invariant, it is a suggestion.
//!
//! # Why these types live inside `finalize`
//!
//! This file was `crates/core/src/verdict.rs` until feature 002 (T007). It moved without a single
//! change to any type, and the move is the whole point.
//!
//! 001 made `Verdict`'s *fields* private, which stops a caller from fabricating an outcome — but it
//! left `Verdict::assemble`, `Reason`, and `Incompleteness` fully public, so any module in the crate
//! could still mint a finding or declare a coverage gap. Three places in `engine.rs` did exactly that.
//! Feature 002 narrows those constructors to `pub(super)` (T008), which makes finalization the only
//! module that can produce a verdict — enforced by the compiler rather than by review (FR-120, FR-121,
//! SC-108).
//!
//! `pub(super)` is why the types are *here* rather than in a sibling module. Rust has no way to say
//! "visible to `crate::finalize` only" from outside that tree: a `pub(in crate::finalize)` item written
//! in a module that is not a descendant of `crate::finalize` does not compile, because the path in a
//! visibility qualifier must name an ancestor of the item. A module that must be the sole producer of a
//! type therefore has to be the module the type is defined in. Research P3 records the two alternatives
//! that do not work.
//!
//! Everything is re-exported from the crate root and through `please_core::verdict`, so no embedder
//! has to know any of this happened.

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
/// **A class names a kind of finding, never a delivery mechanism** (FR-130). That distinction is not
/// pedantry: 001 had a sixth variant, `Encoding`, and it is the reason class selection did not work.
///
/// No rule could declare `Encoding`. It was applied only by the decode path, to observations produced by
/// `override`, `boundary`, and `solicitation` rules — so a decoded finding was gated on its rule's class and
/// then relabelled, and had to satisfy two different filters to be reported. `--classes override` missed an
/// encoded override payload; `--classes encoding` matched nothing at all, because the first gate rejected
/// every rule. The class also contradicted a design statement 001 made explicitly, that an encoding is never
/// itself a finding.
///
/// The delivery mechanism lives in [`Reason::chain`] instead, which is where it was already recorded
/// (FR-132). Disabling decoding is the depth bound, which is what it always was (FR-135).
///
/// `non_exhaustive` from the outset: the set of things an attacker does grows, and adding a sixth class
/// should not break every embedder's `match`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum DetectionClass {
    /// Instructions to disregard, replace, or supersede prior instructions (FR-008).
    Override,
    /// Text hidden by invisible, zero-width, bidi, tag-block, or variation-selector characters (FR-009).
    Concealment,
    /// Characters chosen to resemble others, evaluated per token (FR-010).
    Confusable,
    /// Forged role markers, system-instruction or tool-result impersonation (FR-012).
    Boundary,
    /// Requests for an agent's instructions, configuration, or credentials (FR-013).
    Solicitation,
    /// Content that **addresses the reading agent** rather than the human the document is for
    /// (003 FR-301) — `NOTE TO AI ASSISTANT:`, `Dear assistant,`, `if you are an AI reading this`.
    ///
    /// Distinct from [`Boundary`](Self::Boundary), and the distinction is the reason it is its own class:
    /// forging is a claim about **who is speaking**, addressing is a claim about **who is listening**. A
    /// forged `SYSTEM:` marker claims the platform's authority; `NOTE TO AI:` claims nothing at all — it
    /// simply assumes the reader is a machine.
    ///
    /// In indirect injection the agent is meant to be *processing* content — summarising an email, reading a
    /// tool result, following a skill file. Content that addresses it is anomalous by construction, because
    /// nothing in the legitimate workflow has any reason to talk to it.
    AgentDirected,
}

impl DetectionClass {
    /// Stable wire name. Kept beside the variants so the serialised form cannot drift from them.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Override => "override",
            Self::Concealment => "concealment",
            Self::Confusable => "confusable",
            Self::Boundary => "boundary",
            Self::Solicitation => "solicitation",
            Self::AgentDirected => "agent_directed",
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

/// A region whose content is hidden from a human reader but delivered to the agent in full.
///
/// **The inverse of a [`QuotingContext`], and the distinction is worth stating precisely.** A quoting context
/// says *this text is being shown, not said* — so a match inside one is probably an illustration, and is
/// suppressed. A concealing context says *this text is invisible to the person reviewing the document, and
/// visible to the machine processing it* — which is the opposite inference, and the opposite action.
///
/// An HTML comment in a `SKILL.md`, a README, or any rendered document is read by the agent and never seen by
/// the reviewer who approved the file. That asymmetry between what a human authorises and what a machine
/// receives is the whole shape of indirect injection.
///
/// Nothing in a concealing context may ever be suppressed — see
/// `structure::QuotingMap` and the regression test that pins it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ConcealingContext {
    /// `<!-- ... -->`. Invisible in rendered Markdown and HTML; fully present in the bytes an agent reads.
    HtmlComment,
}

impl ConcealingContext {
    /// Stable wire name, kept beside the variants so the serialised form cannot drift from them.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HtmlComment => "html_comment",
        }
    }
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
///
/// Fields are private and the constructor is `pub(super)`, so only finalization can mint one (FR-121,
/// SC-108). The field this protects hardest is [`matched`](Self::matched): an excerpt is neutralised on
/// the way in here and nowhere else, so a `Reason` that exists is a `Reason` whose excerpt is safe to
/// print. While a detector could build one, that was a property of every detector remembering to call
/// `sanitize_str` — and 001 had a detector-side helper that did it, which is not the same thing as being
/// unable to skip it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reason {
    rule_id: String,
    class: DetectionClass,
    span: Span,
    matched: String,
    severity: u8,
    chain: Vec<Transform>,
    description: String,
    suppressed_by: Option<QuotingContext>,
}

impl Reason {
    /// Build a reason. Visible to finalization only.
    ///
    /// Takes an already-neutralised excerpt, because the neutralisation happens in the caller
    /// (`finalize::into_reason`) where the truncation it may cause can be recorded as a coverage gap. A
    /// function that both sanitised and reported would have to either swallow that fact or return it,
    /// and returning it is what the caller does.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        rule_id: String,
        class: DetectionClass,
        span: Span,
        matched: String,
        severity: u8,
        chain: Vec<Transform>,
        description: String,
        suppressed_by: Option<QuotingContext>,
    ) -> Self {
        Self {
            rule_id,
            class,
            span,
            matched,
            severity,
            chain,
            description,
            suppressed_by,
        }
    }

    /// Namespaced rule identifier, e.g. `override.ignore_previous`. Also the suppression handle.
    pub fn rule_id(&self) -> &str {
        &self.rule_id
    }

    pub fn class(&self) -> DetectionClass {
        self.class
    }

    pub fn span(&self) -> Span {
        self.span
    }

    /// Excerpt of the matching content, **already neutralised** (FR-021).
    ///
    /// Sanitised on the way into this type rather than at each display site, so the guarantee holds for
    /// every consumer including the ones that forget. Sanitise the payload, then style it — never the
    /// reverse.
    pub fn matched(&self) -> &str {
        &self.matched
    }

    pub fn severity(&self) -> u8 {
        self.severity
    }

    /// Empty for a direct match; populated when the match came out of decoded content.
    pub fn chain(&self) -> &[Transform] {
        &self.chain
    }

    /// Why this rule exists, carried from the rule so a finding explains itself without a lookup.
    pub fn description(&self) -> &str {
        &self.description
    }

    /// Present only when a quoting context would normally have suppressed this reason and suppression
    /// was disabled by policy.
    pub fn suppressed_by(&self) -> Option<QuotingContext> {
        self.suppressed_by
    }
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

/// One thing the scan did not examine, **as reported in a verdict**.
///
/// Sealed like [`Reason`]: fields private, constructor `pub(super)`. What a detector records is a
/// [`CoverageGap`](super::evidence::CoverageGap), which carries the same information with public
/// constructors and reaches a verdict only by way of the evidence accumulator. Two types for one fact,
/// distinguished by who may create one — that module explains why at length (FR-122).
///
/// The `with_detail` builder from 001 is gone. Every one of the five call sites used it immediately after
/// `bound()`, which means the two-step construction existed only to make the detail forgettable; the gap
/// constructors now require it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Incompleteness {
    pub(super) cause: IncompleteCause,
    pub(super) configured: Option<u64>,
    pub(super) detail: Option<String>,
}

impl Incompleteness {
    /// Why this part of the input went unexamined.
    pub fn cause(&self) -> IncompleteCause {
        self.cause
    }

    /// The value in force when a bound was reached, so a caller can raise it deliberately. Present for
    /// bounds, absent for failures.
    pub fn configured(&self) -> Option<u64> {
        self.configured
    }

    /// What went unexamined — which rule saturated, which region was skipped, why a target could not be
    /// read.
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
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

/// The complete result of one scan.
///
/// Fields are private and [`Verdict::new`] is `pub(super)`, so [`crate::finalize`] is the only module
/// that can produce one — which makes it the single place the [`Outcome::Clean`] invariant is decided
/// (FR-120, and see the module documentation).
///
/// 001 had a public `assemble` taking a `VerdictParts` struct, and three callers in `engine.rs`. The
/// parts struct is deleted (T020): it carried the reasons and the coverage gaps, so anyone able to build
/// one was deciding what the verdict said, and privacy on `Verdict`'s own fields bought nothing against
/// a caller who could hand in whatever evidence they liked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    outcome: Outcome,
    score: u8,
    risk: RiskLevel,
    reasons: Vec<Reason>,
    reasons_truncated: bool,
    /// Observations quoting suppression hid, each carrying the context that hid it (FR-128).
    ///
    /// Deliberately a separate list from `reasons` rather than a flag on them. These are **not findings**:
    /// they do not score, they do not affect the outcome, and a verdict whose only content is suppressions is
    /// `Clean`. One list with a boolean would leave that distinction to every reader to remember, and the
    /// reader who forgets reintroduces every security-prose false positive.
    suppressed: Vec<Reason>,
    suppressions_truncated: bool,
    incomplete: Vec<Incompleteness>,
    target: TargetRef,
    ruleset: RulesetId,
    engine: EngineId,
}

impl Verdict {
    /// Store an already-decided verdict. Visible to finalization only.
    ///
    /// Deliberately dumb: it derives nothing and validates nothing. Deciding the outcome, ordering the
    /// reasons, and truncating them all happen in [`crate::finalize`], which is where the whole sequence
    /// is visible at once and where the ordering has to precede the truncation.
    ///
    /// 001's `assemble` did the deriving *and* the sorting here, in the type. That reads as defensive —
    /// the invariant lives with the data — but it split the sequence across two files: `engine.rs` had to
    /// sort before truncating, then `assemble` sorted again because it could not know whether the caller
    /// had. Two sorts and one authority is worse than one sort and one authority.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn new(
        outcome: Outcome,
        score: u8,
        risk: RiskLevel,
        reasons: Vec<Reason>,
        reasons_truncated: bool,
        suppressed: Vec<Reason>,
        suppressions_truncated: bool,
        incomplete: Vec<Incompleteness>,
        target: TargetRef,
        ruleset: RulesetId,
        engine: EngineId,
    ) -> Self {
        debug_assert!(
            outcome != Outcome::Clean || (reasons.is_empty() && incomplete.is_empty()),
            "FR-004: a clean verdict requires no reasons and no coverage gaps",
        );
        debug_assert!(
            suppressed.iter().all(|r| r.suppressed_by().is_some()),
            "a suppressed reason must name the context that suppressed it",
        );
        Self {
            outcome,
            score,
            risk,
            reasons,
            reasons_truncated,
            suppressed,
            suppressions_truncated,
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

    /// What quoting suppression hid, each annotated with the context that hid it (FR-128, SC-110).
    ///
    /// Answers "what did the heuristic change here?" from one scan. Empty when suppression is disabled by
    /// policy — in that case the same observations appear in [`reasons`](Self::reasons), annotated via
    /// [`Reason::suppressed_by`].
    ///
    /// These are not findings. They do not contribute to [`score`](Self::score) and cannot make an outcome
    /// `RiskFound`.
    pub fn suppressed(&self) -> &[Reason] {
        &self.suppressed
    }

    /// True when more was suppressed than the reason bound reports.
    pub fn suppressions_truncated(&self) -> bool {
        self.suppressions_truncated
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

    /// One line describing this verdict, for a log or a denial message.
    ///
    /// Deliberately short and deliberately specific: this is what a blocked caller sees, and "blocked by
    /// policy" tells them nothing they can act on. Naming the worst rule and the count gives them
    /// somewhere to start.
    pub fn summary(&self) -> String {
        match self.outcome {
            Outcome::Clean => "clean".to_string(),
            Outcome::Inconclusive => {
                let causes: Vec<&str> = self.incomplete.iter().map(|i| i.cause.as_str()).collect();
                format!("inconclusive ({})", causes.join(", "))
            }
            Outcome::RiskFound => {
                let worst = self
                    .reasons
                    .iter()
                    .max_by_key(|r| r.severity)
                    .map(|r| r.rule_id.as_str())
                    .unwrap_or("unknown");
                let extra = self.reasons.len().saturating_sub(1);
                let more = if extra > 0 {
                    format!(" (+{extra} more)")
                } else {
                    String::new()
                };
                format!("{:?} risk, score {}: {worst}{more}", self.risk, self.score)
            }
        }
    }
}
