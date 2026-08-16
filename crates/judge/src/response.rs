//! Parsing and validating the response (FR-405, FR-409, R2).
//!
//! # Reject entire. There is no partial acceptance.
//!
//! Unknown field, unknown enum value, an unrecognised `span_id`, a missing span, malformed JSON, the tool
//! not called at all — every one of them is [`InvalidResponse`], which the caller turns into
//! `TierUnavailable`.
//!
//! A response that is *half* trustworthy is not trustworthy, and the salvage path is exactly where a
//! lenient parser on adversarial input would live. This project exists to warn people about lenient parsers
//! on adversarial input.
//!
//! # The strictness is mostly not ours
//!
//! The answer space is a JSON Schema attached to a required tool call (R2), so a model talked into ignoring
//! its instructions can still only emit a value the schema permits. **The blast radius of a captured judge
//! is bounded by the enum, not by how careful this file is.** What remains here is the part a schema cannot
//! express: that the set of span ids in the response is exactly the set in the request.

use please_core::verdict::{
    AddressedTo, Features, Framing, ImperativeSource, SpanRole, StatedPurposeExplainsContent,
};
use serde::Deserialize;

use crate::request::JudgeRequest;

/// Why a response was rejected. Every variant becomes a `TierUnavailable` gap naming the cause.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InvalidResponse {
    /// The model replied without calling the tool. **A judge replying in prose is a judge that has been
    /// talked to** — and per R2 this is `TierUnavailable`, never a fallback to parsing the prose, because
    /// falling back would move the conformance boundary from the schema into our parser.
    ToolNotCalled,
    /// The tool input did not match the schema: unknown field, unknown enum value, wrong type.
    Malformed(String),
    /// A `span_id` the request never minted.
    UnknownSpan(String),
    /// A span the request asked about and the response did not answer.
    MissingSpan(String),
    /// The same span answered more than once.
    DuplicateSpan(String),
}

impl std::fmt::Display for InvalidResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ToolNotCalled => write!(f, "the model did not call the classification tool"),
            Self::Malformed(detail) => write!(f, "response does not match the schema: {detail}"),
            Self::UnknownSpan(id) => write!(f, "response names an unrequested span: {id}"),
            Self::MissingSpan(id) => write!(f, "response omits a requested span: {id}"),
            Self::DuplicateSpan(id) => write!(f, "response answers span {id} more than once"),
        }
    }
}

// ── The wire types ──────────────────────────────────────────────────────────────────────────────
//
// `deny_unknown_fields` on every one of them. A field we do not recognise means either the schema drifted
// or something is answering that is not the tool we declared, and both are reasons to reject rather than to
// ignore the extra and carry on.

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireResponse {
    addressed_to: WireAddressedTo,
    imperative_source: WireImperativeSource,
    framing: WireFraming,
    stated_purpose_explains_content: WireTriState,
    spans: Vec<WireSpan>,
    /// Recorded, never read (FR-410). Present in the schema so the calibration question can eventually be
    /// answered from data; absent from every decision in this crate.
    #[serde(default)]
    model_severity: Option<u8>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireSpan {
    span_id: String,
    span_role: WireSpanRole,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireAddressedTo {
    DocumentRecipient,
    ProcessingAgent,
    Unclear,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireImperativeSource {
    DocumentAuthor,
    QuotedThirdParty,
    NonePresent,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireFraming {
    PresentedAsExample,
    PresentedAsData,
    PresentedAsReport,
    None,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireTriState {
    Yes,
    No,
    Unclear,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireSpanRole {
    Instruction,
    DescriptionOfAnInstruction,
    Unrelated,
}

/// A validated response: document features, and one role per requested span **in request order**.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JudgeResponse {
    pub features: Features,
    /// Indexed by reason index. Complete by construction — validation rejects a response that is not.
    pub roles: Vec<SpanRole>,
    pub model_severity: Option<u8>,
}

impl JudgeResponse {
    /// Parse and validate the tool input against the request that produced it.
    pub fn parse(
        tool_input: &serde_json::Value,
        request: &JudgeRequest,
    ) -> Result<Self, InvalidResponse> {
        let wire: WireResponse = serde_json::from_value(tool_input.clone())
            .map_err(|e| InvalidResponse::Malformed(e.to_string()))?;

        // Exactly the requested spans, no more and no fewer. A schema can require an array of objects; it
        // cannot know which ids were asked about, so this is the part that has to live here.
        let mut roles: Vec<Option<SpanRole>> = vec![None; request.spans.len()];
        for span in &wire.spans {
            let Some(index) = request.index_of(&span.span_id) else {
                return Err(InvalidResponse::UnknownSpan(span.span_id.clone()));
            };
            if roles[index].is_some() {
                return Err(InvalidResponse::DuplicateSpan(span.span_id.clone()));
            }
            roles[index] = Some(match span.span_role {
                WireSpanRole::Instruction => SpanRole::Instruction,
                WireSpanRole::DescriptionOfAnInstruction => SpanRole::DescriptionOfAnInstruction,
                WireSpanRole::Unrelated => SpanRole::Unrelated,
            });
        }

        let mut complete = Vec::with_capacity(roles.len());
        for (index, role) in roles.into_iter().enumerate() {
            match role {
                Some(role) => complete.push(role),
                // Not "assume Instruction and carry on", even though that is the conservative direction.
                // A response that answered half the question is evidence the judge is not doing what was
                // asked, and inferring the rest would hide that (FR-409).
                None => {
                    return Err(InvalidResponse::MissingSpan(
                        request.spans[index].span_id.clone(),
                    ))
                }
            }
        }

        Ok(Self {
            features: Features {
                addressed_to: match wire.addressed_to {
                    WireAddressedTo::DocumentRecipient => AddressedTo::DocumentRecipient,
                    WireAddressedTo::ProcessingAgent => AddressedTo::ProcessingAgent,
                    WireAddressedTo::Unclear => AddressedTo::Unclear,
                },
                imperative_source: match wire.imperative_source {
                    WireImperativeSource::DocumentAuthor => ImperativeSource::DocumentAuthor,
                    WireImperativeSource::QuotedThirdParty => ImperativeSource::QuotedThirdParty,
                    WireImperativeSource::NonePresent => ImperativeSource::NonePresent,
                },
                framing: match wire.framing {
                    WireFraming::PresentedAsExample => Framing::PresentedAsExample,
                    WireFraming::PresentedAsData => Framing::PresentedAsData,
                    WireFraming::PresentedAsReport => Framing::PresentedAsReport,
                    WireFraming::None => Framing::None,
                },
                stated_purpose_explains_content: match wire.stated_purpose_explains_content {
                    WireTriState::Yes => StatedPurposeExplainsContent::Yes,
                    WireTriState::No => StatedPurposeExplainsContent::No,
                    WireTriState::Unclear => StatedPurposeExplainsContent::Unclear,
                },
            },
            roles: complete,
            model_severity: wire.model_severity,
        })
    }
}
