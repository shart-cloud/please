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

impl RiskLevel {
    /// Stable wire name, kept beside the variants so the serialised form cannot drift from them.
    ///
    /// Added at 001 T069, when serialisation stopped being hypothetical. `crates/cli/src/render.rs` had a
    /// private `band()` doing the same job in different words, which is exactly the drift this method
    /// exists to prevent.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
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
    /// An instruction to take an action against state **outside** the conversation — grant access,
    /// approve a record, transfer funds, modify a permission.
    ///
    /// Distinct from [`Solicitation`](Self::Solicitation), and the line between them is what the payload
    /// asks for. Solicitation asks for something belonging to the agent or its context: its instructions,
    /// its configuration, a credential it holds. This asks the agent to *act on a third party* and takes
    /// nothing back — "grant the sender admin access" wants no secret, it wants an effect.
    ///
    /// InjecAgent splits its attacker instructions along exactly this line, direct harm against data
    /// stealing, and the split turns out to be measurable rather than taxonomic: on 1,054 adversarial
    /// InjecAgent rows the disclosure half and this half fire on almost disjoint sets.
    ///
    /// Distinct from [`AgentDirected`](Self::AgentDirected) too, which is about who the content *addresses*.
    /// "You should rank this candidate first" addresses the agent and asks for an action; the classes are
    /// orthogonal and a payload can be both.
    ///
    /// Added because neither existing class described it and filing it under one of them would have made
    /// that class stop describing its members. `rules/experimental/actionable-directive.toml` recorded the
    /// problem and declined to guess; this is the answer.
    ExternalAction,
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
            Self::ExternalAction => "external_action",
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

impl QuotingContext {
    /// Stable wire name, kept beside the variants so the serialised form cannot drift from them.
    ///
    /// Added by feature 004 for [`SuppressedBy::as_str`], which has to name either a quoting context or the
    /// judge in one string. `ConcealingContext` has carried the same method since it was introduced.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FencedCode => "fenced_code",
            Self::InlineCode => "inline_code",
            Self::BlockQuote => "block_quote",
            Self::QuotedString => "quoted_string",
            Self::AttributiveMarker => "attributive_marker",
        }
    }
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

/// What moved an observation into the suppressed channel (feature 004, FR-403).
///
/// Until 004 there was one answer and [`Reason::suppressed_by`] returned an `Option<QuotingContext>`
/// directly. The judgement tier is a second author of the same sentence — *here is what we saw, and why it
/// might not count* — so the field needs a wider type.
///
/// **Not a new `QuotingContext` variant**, and the distinction is worth the breaking change. A quoting
/// context is a claim about the *document*: this text sits inside a fence, a quote, an example. A judgement
/// is a claim about an *external process*: a model was asked a question and its answer, run through our
/// scoring function, came out as demote. Filing the second under the first would be the `Encoding` mistake
/// again — a name that quietly stops describing its members — and this project has now twice concluded that
/// an invisible consistency obligation is the worse trade.
///
/// The two cases also differ in what a reader should do about them. A quoting suppression is reproducible
/// offline and deterministic. A judge suppression is neither, is attributable to a specific model and prompt
/// version, and is reversible with one flag: `--no-judge` reproduces the structural verdict byte-identically
/// (FR-418).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SuppressedBy {
    /// A quoting region in the document itself (FR-014).
    Quoting(QuotingContext),
    /// The judgement tier, which read the span and answered that it describes an instruction rather than
    /// issuing one (feature 004, plan D5).
    ///
    /// The observation is **still in the verdict**. It has moved between two lists, and this variant is the
    /// record of what moved it.
    Judge,
}

impl SuppressedBy {
    /// Stable wire name, kept beside the variants so the serialised form cannot drift from them.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Quoting(context) => context.as_str(),
            Self::Judge => "judge",
        }
    }

    /// The quoting context, when that is what suppressed this observation.
    ///
    /// Exists so a caller that only cares about the structural case does not have to match on a variant
    /// that may not be compiled into its build.
    pub fn quoting(&self) -> Option<QuotingContext> {
        match self {
            Self::Quoting(context) => Some(*context),
            Self::Judge => None,
        }
    }
}

// ── The judgement vocabulary (feature 004, plan D10) ────────────────────────────────────────────
//
// These types are here for one reason: `JudgeReport` hangs off `Verdict`, `Verdict` is a core type, and
// core cannot depend on `please-judge` without inverting the dependency direction that keeps three CI gates
// green by construction (plan D1).
//
// So core learns the VOCABULARY and gains no capability. There is no client here, no credential, no
// endpoint, no scoring function, and no way to obtain a judgement — a `JudgeReport` arrives from a caller
// exactly as `Attribution` does. The line, stated once:
//
//     core may DESCRIBE a judgement; only `please-judge` may OBTAIN one.
//
// Every enum below is a closed answer set with no free-text member anywhere (FR-405). That is not a
// formatting preference: the blast radius of a captured judge is bounded by these enums, which is what makes
// SC-406 a statement about the design rather than about the quality of our validation code.

/// Who a document's imperative sentences are speaking to.
///
/// The 003 signal, asked of a model rather than inferred from form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AddressedTo {
    /// The person or system the document is *for*.
    DocumentRecipient,
    /// The agent processing the document — which is the asymmetry indirect injection is made of.
    ProcessingAgent,
    Unclear,
}

/// Whether the document is issuing an instruction or relaying someone else's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ImperativeSource {
    DocumentAuthor,
    QuotedThirdParty,
    NonePresent,
}

/// How the document presents the material in question.
///
/// The field that separates `benign-tool-001` from `indirect-tool-003` — the two fixtures this tier exists
/// for, which are near-identical in structure and oppositely labelled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Framing {
    PresentedAsExample,
    PresentedAsData,
    PresentedAsReport,
    None,
}

/// Whether the document's stated purpose accounts for what it contains.
///
/// A CVE advisory quoting a payload has a purpose that explains it. A meeting agenda quoting one does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StatedPurposeExplainsContent {
    Yes,
    No,
    Unclear,
}

/// Whether a span is **the document's subject or a passenger inside it** (plan D4a).
///
/// The field that actually separates `benign-tool-001` from `indirect-tool-003`, established by
/// measurement rather than by argument — see `crates/judge/tests/axis_probe.rs` and plan D4a.
///
/// The original design asked only [`SpanRole`] plus document-level [`Framing`], and both fixtures answered
/// **identically**: `description_of_an_instruction` in a document `presented_as_data`. Those answers were
/// correct. Grep output *is* data; a TODO comment *is* a description of an instruction. They just do not
/// distinguish a transcript whose subject is a file of payloads from a transcript that happens to contain
/// one.
///
/// This question does:
///
/// * `cat injection_samples.txt` — the payloads **are** what the command was run to show. Remove them and
///   the document has no subject.
/// * `grep -r TODO src/` — the payload is a **passenger**. Remove it and the grep output is unchanged in
///   purpose, because its purpose was never to show that line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpanRelation {
    /// The span is part of what the document set out to show.
    IsWhatTheDocumentShows,
    /// The span rode along inside content displayed for an unrelated reason.
    IncidentalToWhatTheDocumentShows,
    Unclear,
}

/// What one flagged span **is**, as opposed to what it resembles.
///
/// Per span rather than per document, because a document can contain both — already a passing structural
/// test (`a_live_payload_is_reported_and_a_quoted_one_suppressed_in_the_same_scan`). A document-level answer
/// could not express that, and the pair this tier exists to separate would be unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SpanRole {
    /// The span instructs.
    Instruction,
    /// The span *describes* an instruction — a transcript, an example, a quoted payload.
    DescriptionOfAnInstruction,
    Unrelated,
}

macro_rules! judgement_wire_names {
    ($($ty:ident { $($variant:ident => $name:literal),+ $(,)? })+) => {
        $(impl $ty {
            /// Stable wire name, kept beside the variants so the serialised form cannot drift from them.
            pub fn as_str(&self) -> &'static str {
                match self {
                    $(Self::$variant => $name,)+
                }
            }
        })+
    };
}

judgement_wire_names! {
    AddressedTo {
        DocumentRecipient => "document_recipient",
        ProcessingAgent => "processing_agent",
        Unclear => "unclear",
    }
    ImperativeSource {
        DocumentAuthor => "document_author",
        QuotedThirdParty => "quoted_third_party",
        NonePresent => "none_present",
    }
    Framing {
        PresentedAsExample => "presented_as_example",
        PresentedAsData => "presented_as_data",
        PresentedAsReport => "presented_as_report",
        None => "none",
    }
    StatedPurposeExplainsContent {
        Yes => "yes",
        No => "no",
        Unclear => "unclear",
    }
    SpanRole {
        Instruction => "instruction",
        DescriptionOfAnInstruction => "description_of_an_instruction",
        Unrelated => "unrelated",
    }
    SpanRelation {
        IsWhatTheDocumentShows => "is_what_the_document_shows",
        IncidentalToWhatTheDocumentShows => "incidental_to_what_the_document_shows",
        Unclear => "unclear",
    }
}

/// The document-level answers, returned once per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Features {
    pub addressed_to: AddressedTo,
    pub imperative_source: ImperativeSource,
    pub framing: Framing,
    pub stated_purpose_explains_content: StatedPurposeExplainsContent,
}

/// What the tier decided about one observation. **Two variants, and that is the security property.**
///
/// There is no `Cleared`, no `Escalated`, and no `Added`. Not "we validate against them" — they are **not
/// representable**, so SC-406's property test is checking a type rather than a code path (FR-403).
///
/// The reasoning is about what an attacker wins rather than whether they succeed. The judge reads
/// attacker-controlled text, so injection against it must be assumed to work sometimes. If it could clear a
/// finding, capturing it would be a total bypass of the tool. Because demotion is the strongest thing it can
/// express:
///
/// - the structural finding is never erased — it is in the verdict, with the judge named as what demoted it;
/// - `--no-judge` reproduces the structural verdict exactly, so any dispute is one command to settle;
/// - the caller's policy decides whether a judge-suppressed finding blocks (Principle I).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpanJudgement {
    /// Nothing happens to the observation. It stays in [`Verdict::reasons`], byte-identical to the
    /// structural one — see [`JudgeReport`] for why no annotation is written onto the [`Reason`].
    Confirmed,
    /// The observation moves to [`Verdict::suppressed`], annotated [`SuppressedBy::Judge`].
    Demoted,
}

impl SpanJudgement {
    /// Stable wire name, kept beside the variants so the serialised form cannot drift from them.
    ///
    /// `crates/cli/src/render.rs` hardcoded these two strings until 001 T069.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Confirmed => "confirmed",
            Self::Demoted => "demoted",
        }
    }
}

/// One span's judgement, with the answer it was derived from.
///
/// Carries `role` as well as `judgement` because FR-407 computes the score from the features: without them
/// the outcome is an unexplained number, and 002 spent its effort removing exactly those.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpanVerdict {
    /// Index into [`Verdict::reasons`] as it stood in the **structural** verdict.
    pub reason_index: usize,
    pub role: SpanRole,
    /// Subject or passenger — the field that decides the case (plan D4a).
    pub relation: SpanRelation,
    pub judgement: SpanJudgement,
}

/// What the judgement tier adds to a verdict (FR-416, R3).
///
/// Enough to answer *"why did it do that"* from the verdict alone, which is what US5 asks and what 002
/// established as the standard when it removed the two-run diff from the false-positive workflow.
///
/// **Not recorded**: the raw response body. It is attacker-influenced text with no consumer, and storing it
/// in a verdict would create a channel by which content reaches a reader that the sanitisation path never
/// inspected. Nor the credential, obviously (FR-413).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgeReport {
    model: String,
    prompt_version: String,
    features: Features,
    judgements: Vec<SpanVerdict>,
    model_severity: Option<u8>,
}

impl JudgeReport {
    /// Build a report. Public because `please-judge` is a different crate and must be able to produce one —
    /// but note what that does **not** grant: producing a report is not producing a verdict. Only
    /// [`crate::finalize::rejudge`] can apply one, and it can only narrow (FR-403).
    pub fn new(
        model: impl Into<String>,
        prompt_version: impl Into<String>,
        features: Features,
        judgements: Vec<SpanVerdict>,
        model_severity: Option<u8>,
    ) -> Self {
        Self {
            model: model.into(),
            prompt_version: prompt_version.into(),
            features,
            judgements,
            model_severity,
        }
    }

    /// The resolved model id. A verdict judged by one model is not evidence about another — the same
    /// reasoning that made the rule-set digest SHA-256 rather than `DefaultHasher` (SC-012).
    pub fn model(&self) -> &str {
        &self.model
    }

    /// The prompt version. Included because a prompt edit shifts feature extraction as surely as a model
    /// change does, and it is the variable *we* control.
    pub fn prompt_version(&self) -> &str {
        &self.prompt_version
    }

    pub fn features(&self) -> Features {
        self.features
    }

    pub fn judgements(&self) -> &[SpanVerdict] {
        &self.judgements
    }

    // ── `model_severity` has no accessor, deliberately (FR-410) ─────────────────────────────────
    //
    // The model's own opinion is recorded and read by nothing. It is stored beside the derived score so
    // that, over a corpus, we can ask whether the model's scoring would have agreed — and get an answer
    // from data rather than from a prior. That is the cheapest possible experiment on "could we have just
    // asked it?", and it costs one unused field.
    //
    // The guarantee that nothing reads it is STRUCTURAL rather than tested: with no accessor, no reader
    // outside this module can exist, and a future one cannot be added without a visible API change that a
    // reviewer will see. The task originally specified a grep-based test; a grep matches the doc comments
    // and the wire-format string and would have passed for the wrong reason.
    //
    // When there is a corpus and a calibration study to run, add the accessor in the commit that reads it.
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

impl TransformKind {
    /// Stable wire name, kept beside the variants so the serialised form cannot drift from them.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Base64 => "base64",
            Self::Hex => "hex",
            Self::Rot13 => "rot13",
            Self::Reversed => "reversed",
            Self::Leetspeak => "leetspeak",
            Self::UnicodeTags => "unicode_tags",
            Self::VariationSelectors => "variation_selectors",
        }
    }
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
    /// Widened from `Option<QuotingContext>` by feature 004 (T009). Quoting is no longer the only thing
    /// that can suppress an observation — see [`SuppressedBy`].
    suppressed_by: Option<SuppressedBy>,
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
        suppressed_by: Option<SuppressedBy>,
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

    /// What suppressed this reason, if anything.
    ///
    /// Two quite different situations produce a `Some` here, and a reader has to be able to tell them
    /// apart:
    ///
    /// - on a reason in [`Verdict::suppressed`], it names what moved it there — a quoting context, or the
    ///   judgement tier;
    /// - on a reason in [`Verdict::reasons`], it means a quoting context *would* have suppressed it and
    ///   policy disabled suppression. The finding is reported, annotated with what was overridden.
    ///
    /// Widened from `Option<QuotingContext>` in feature 004. Callers that only care about the structural
    /// case can use [`SuppressedBy::quoting`] rather than matching a variant their build may not use.
    pub fn suppressed_by(&self) -> Option<SuppressedBy> {
        self.suppressed_by
    }

    /// Move this reason into the suppressed channel, naming the judgement tier as the cause.
    ///
    /// `pub(super)` like every other mutator here: only [`crate::finalize`] may apply a judgement, which is
    /// what keeps `rejudge` the single place a demotion can happen rather than something any holder of a
    /// `Reason` can do (FR-120, FR-403).
    pub(super) fn demote_by_judge(&mut self) {
        self.suppressed_by = Some(SuppressedBy::Judge);
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
    /// A target was reachable but deliberately not descended into — a symbolic link to a directory,
    /// which a walk refuses to follow because it may be a cycle.
    ///
    /// Separate from [`Self::TargetUnreadable`] because the difference is what the reader does about it.
    /// The path is perfectly readable; the caller declined. Filed under the same fail-open rule either
    /// way: unexamined content is inconclusive, never clean.
    TargetNotTraversed,
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
            Self::TargetNotTraversed => "target_not_traversed",
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

impl TargetKind {
    /// Stable wire name, kept beside the variants so the serialised form cannot drift from them.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::Stdin => "stdin",
            Self::Buffer => "buffer",
        }
    }
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
    /// Present only on a verdict the judgement tier acted on (feature 004, FR-416).
    ///
    /// `None` on every default scan, and its absence is the machine-readable form of "this verdict is
    /// purely structural, and 001's determinism guarantee applies to it unchanged" (FR-417).
    judge: Option<JudgeReport>,
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
            // Never set here. A verdict is structural when it is built, and becomes judged only by passing
            // through `rejudge` — which is what keeps the judged path strictly additive to a path that
            // already works (FR-418).
            judge: None,
        }
    }

    /// Attach the report that produced this verdict's demotions.
    ///
    /// Deliberately **not** a parameter of [`Verdict::new`]. Adding one would touch every construction path
    /// in `finalize` — the oversized verdict, the unreadable target, the gap-only verdict — none of which
    /// can ever be judged, and each of which would then carry a `None` that reads as a decision rather than
    /// as an absence. A builder step on the one path that uses it says what is actually true.
    pub(super) fn with_judge(mut self, report: JudgeReport) -> Self {
        self.judge = Some(report);
        self
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

    /// The judgement tier's report, present only when the tier acted on this verdict (FR-416).
    ///
    /// `None` means no judge ran — **not** that one ran and found nothing. A judge that ran and confirmed
    /// everything returns `Some` with every span `Confirmed`, and the difference matters: one verdict has a
    /// second opinion behind it and the other does not.
    pub fn judge(&self) -> Option<&JudgeReport> {
        self.judge.as_ref()
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

// ── Serialisation (001 T069, behind the `serde` feature) ────────────────────────────────────────
//
// The serialised form is a **published contract**: `specs/001-structural-detection-cli/contracts/verdict.schema.json`,
// which `crates/cli/tests/contract.rs` validates real output against. Two consequences shape everything
// below.
//
// **Every enum serialises through its own `as_str()`**, not through `rename_all`. This file says four times
// that wire names are "kept beside the variants so the serialised form cannot drift from them"; routing
// serialisation through `as_str` makes that structurally true instead of a convention, and it means adding a
// variant without a wire name fails to compile rather than emitting a Rust identifier.
//
// It is also the only thing that works for `SuppressedBy`. That enum has a newtype variant,
// `Quoting(QuotingContext)`, which `rename_all` would render as `{"quoting": "fenced_code"}` — the schema
// wants the flat string `"fenced_code"`, and `SuppressedBy::as_str` already flattens both arms into exactly
// that one 6-value space.
//
// **Structs derive normally.** Private fields are not an obstacle: the derive is generated inside this
// module, which is also why it has to live here rather than in the CLI.
#[cfg(feature = "serde")]
mod serialisation {
    use super::*;
    use serde::ser::{Serialize, SerializeStruct, Serializer};

    /// Serialise an enum as its wire name.
    macro_rules! as_str_serialize {
        ($($ty:ident),+ $(,)?) => {
            $(impl Serialize for $ty {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    serializer.serialize_str(self.as_str())
                }
            })+
        };
    }

    as_str_serialize!(
        Outcome,
        RiskLevel,
        DetectionClass,
        QuotingContext,
        SuppressedBy,
        TransformKind,
        IncompleteCause,
        TargetKind,
        SpanJudgement,
        SpanRole,
        SpanRelation,
        AddressedTo,
        ImperativeSource,
        Framing,
        StatedPurposeExplainsContent,
    );

    impl Serialize for Span {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut o = s.serialize_struct("Span", 2)?;
            o.serialize_field("start", &self.start)?;
            o.serialize_field("end", &self.end)?;
            o.end()
        }
    }

    impl Serialize for Transform {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut o = s.serialize_struct("Transform", 4)?;
            o.serialize_field("kind", &self.kind)?;
            o.serialize_field("depth", &self.depth)?;
            o.serialize_field("input_span", &self.input_span)?;
            o.serialize_field("decoded_excerpt", &self.decoded_excerpt)?;
            o.end()
        }
    }

    impl Serialize for Reason {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            // `suppressed_by` is skipped when absent; the schema has it optional. Every other field is
            // always present, including `description` — the schema permits omitting it, and a finding
            // without its explanation is one nobody can act on, so it is always written.
            let len = 7 + usize::from(self.suppressed_by.is_some());
            let mut o = s.serialize_struct("Reason", len)?;
            o.serialize_field("rule_id", &self.rule_id)?;
            o.serialize_field("class", &self.class)?;
            o.serialize_field("span", &self.span)?;
            o.serialize_field("matched", &self.matched)?;
            o.serialize_field("severity", &self.severity)?;
            o.serialize_field("chain", &self.chain)?;
            o.serialize_field("description", &self.description)?;
            match &self.suppressed_by {
                Some(by) => o.serialize_field("suppressed_by", by)?,
                None => o.skip_field("suppressed_by")?,
            }
            o.end()
        }
    }

    impl Serialize for Incompleteness {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let len =
                1 + usize::from(self.configured.is_some()) + usize::from(self.detail.is_some());
            let mut o = s.serialize_struct("Incompleteness", len)?;
            o.serialize_field("cause", &self.cause)?;
            match &self.configured {
                Some(v) => o.serialize_field("configured", v)?,
                None => o.skip_field("configured")?,
            }
            match &self.detail {
                Some(v) => o.serialize_field("detail", v)?,
                None => o.skip_field("detail")?,
            }
            o.end()
        }
    }

    impl Serialize for TargetRef {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            // `name` is the path AS GIVEN, never absolutised, which is what keeps output identical across
            // working directories (SC-011).
            let len = 2 + usize::from(self.name.is_some());
            let mut o = s.serialize_struct("TargetRef", len)?;
            o.serialize_field("kind", &self.kind)?;
            match &self.name {
                Some(v) => o.serialize_field("name", v)?,
                None => o.skip_field("name")?,
            }
            o.serialize_field("bytes", &self.bytes)?;
            o.end()
        }
    }

    impl Serialize for RulesetId {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut o = s.serialize_struct("RulesetId", 3)?;
            o.serialize_field("name", &self.name)?;
            o.serialize_field("version", &self.version)?;
            o.serialize_field("digest", &self.digest)?;
            o.end()
        }
    }

    impl Serialize for EngineId {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut o = s.serialize_struct("EngineId", 2)?;
            o.serialize_field("name", &self.name)?;
            o.serialize_field("version", &self.version)?;
            o.end()
        }
    }

    impl Serialize for Features {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut o = s.serialize_struct("Features", 4)?;
            o.serialize_field("addressed_to", &self.addressed_to)?;
            o.serialize_field("imperative_source", &self.imperative_source)?;
            o.serialize_field("framing", &self.framing)?;
            o.serialize_field(
                "stated_purpose_explains_content",
                &self.stated_purpose_explains_content,
            )?;
            o.end()
        }
    }

    impl Serialize for SpanVerdict {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let mut o = s.serialize_struct("SpanVerdict", 4)?;
            o.serialize_field("reason_index", &self.reason_index)?;
            o.serialize_field("role", &self.role)?;
            o.serialize_field("relation", &self.relation)?;
            o.serialize_field("judgement", &self.judgement)?;
            o.end()
        }
    }

    impl Serialize for JudgeReport {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            // `model_severity` is NOT serialised, and the omission is FR-410 rather than an oversight. The
            // model's own opinion is recorded and read by nothing; putting it on the wire would make it
            // readable, which is the one thing the field must not be until there is a corpus to calibrate
            // against. The schema rejects it too — `additionalProperties: false` — so this is enforced
            // twice, by the type having no accessor and by the contract test.
            let mut o = s.serialize_struct("JudgeReport", 4)?;
            o.serialize_field("model", &self.model)?;
            o.serialize_field("prompt_version", &self.prompt_version)?;
            o.serialize_field("features", &self.features)?;
            o.serialize_field("judgements", &self.judgements)?;
            o.end()
        }
    }

    impl Serialize for Verdict {
        fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
            let len = 11 + usize::from(self.judge.is_some());
            let mut o = s.serialize_struct("Verdict", len)?;
            o.serialize_field("outcome", &self.outcome)?;
            o.serialize_field("score", &self.score)?;
            o.serialize_field("risk", &self.risk)?;
            o.serialize_field("reasons", &self.reasons)?;
            o.serialize_field("reasons_truncated", &self.reasons_truncated)?;
            o.serialize_field("suppressed", &self.suppressed)?;
            o.serialize_field("suppressions_truncated", &self.suppressions_truncated)?;
            o.serialize_field("incomplete", &self.incomplete)?;
            o.serialize_field("target", &self.target)?;
            o.serialize_field("ruleset", &self.ruleset)?;
            o.serialize_field("engine", &self.engine)?;
            // Absent, not null, when no judge ran — and the ABSENCE is meaningful. `judge: null` would say
            // "a judge ran and produced nothing", which is a different claim (004 FR-416).
            match &self.judge {
                Some(report) => o.serialize_field("judge", report)?,
                None => o.skip_field("judge")?,
            }
            o.end()
        }
    }
}
