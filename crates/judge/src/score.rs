//! Features → judgement (FR-407). **This project computes the score. The model does not.**
//!
//! # Why the model is not asked to score
//!
//! Ask a model to find a problem and it will find one. A null result reads as a failure to be useful, so
//! the pull is toward giving you something with meat on it — and a security context sharpens that pull,
//! because overstating looks careful and understating looks negligent. Every mitigation phrased as *"be
//! conservative"* is an instruction competing with that pull, and instructions lose to incentives.
//!
//! So the incentive is removed rather than argued with. **A model that is not scoring anything has nothing
//! to inflate.** Asked *"who is this sentence addressed to?"* there is no impressive answer: the question
//! has no severe end to drift toward.
//!
//! # The function is deliberately trivial, and that is not laziness
//!
//! How features *should* combine into a score is a calibration question, calibration needs a corpus, and
//! this project does not have one yet. Inventing weights now would repeat 001's provisional band boundaries
//! with less excuse the second time — so the rule below is the smallest thing that expresses the axis, and
//! tuning waits for evidence (spec Assumptions, plan open question 4).
//!
//! The rule: **`description_of_an_instruction`, corroborated by a document-level field, demotes. Anything
//! else confirms.**
//!
//! # Every ambiguity resolves toward confirming
//!
//! `unclear` everywhere demotes nothing, and that is a security property rather than a default. Abstention
//! must never be cheaper for an attacker than honesty — if answering `unclear` to everything suppressed
//! findings, the cheapest attack on this tier would be to make the document confusing, which is free.

use please_core::verdict::{
    AddressedTo, Features, Framing, ImperativeSource, SpanJudgement, SpanRole,
    StatedPurposeExplainsContent,
};

/// Decide one span's fate from its role and the document it sits in (FR-403, FR-407).
pub fn judge_span(role: SpanRole, features: Features) -> SpanJudgement {
    // The per-span answer is necessary. A span that instructs, or that has nothing to do with anything,
    // is not something a document-level framing can talk us out of reporting.
    if role != SpanRole::DescriptionOfAnInstruction {
        return SpanJudgement::Confirmed;
    }

    if corroborates_display(features) {
        SpanJudgement::Demoted
    } else {
        SpanJudgement::Confirmed
    }
}

/// Whether the document as a whole supports reading this span as displayed rather than issued.
///
/// **Corroboration is required, not optional.** `span_role` alone is one answer from one model about one
/// excerpt, and it is the single field a captured judge would flip. Requiring a document-level field to
/// agree means capturing the tier takes two consistent lies instead of one — which is not a large barrier,
/// and is a larger one than nothing.
///
/// Any single condition suffices, because they are alternative descriptions of the same situation rather
/// than a checklist: a document that presents its content as an example, or as data, or as a report, or
/// that is relaying somebody else's instruction, or whose stated purpose accounts for instruction-shaped
/// text being present, is a document in which a quoted payload is expected.
fn corroborates_display(features: Features) -> bool {
    // Addressed to the processing agent is DISQUALIFYING rather than merely unhelpful. A document speaking
    // to the agent reading it is the shape indirect injection is made of (003), and "this is only an
    // example, agent" is precisely what a payload would say.
    if features.addressed_to == AddressedTo::ProcessingAgent {
        return false;
    }

    matches!(
        features.framing,
        Framing::PresentedAsExample | Framing::PresentedAsData | Framing::PresentedAsReport
    ) || features.imperative_source == ImperativeSource::QuotedThirdParty
        || features.stated_purpose_explains_content == StatedPurposeExplainsContent::Yes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(
        addressed_to: AddressedTo,
        imperative_source: ImperativeSource,
        framing: Framing,
        stated_purpose_explains_content: StatedPurposeExplainsContent,
    ) -> Features {
        Features {
            addressed_to,
            imperative_source,
            framing,
            stated_purpose_explains_content,
        }
    }

    /// The neutral document: every field at its least informative value.
    fn unclear_everywhere() -> Features {
        features(
            AddressedTo::Unclear,
            ImperativeSource::NonePresent,
            Framing::None,
            StatedPurposeExplainsContent::Unclear,
        )
    }

    /// T037. **Abstention must never be cheaper for an attacker than honesty.**
    #[test]
    fn unclear_everywhere_demotes_nothing() {
        for role in [
            SpanRole::Instruction,
            SpanRole::DescriptionOfAnInstruction,
            SpanRole::Unrelated,
        ] {
            assert_eq!(
                judge_span(role, unclear_everywhere()),
                SpanJudgement::Confirmed,
                "a document the model could say nothing about must leave the structural verdict standing"
            );
        }
    }

    /// A span that instructs is confirmed however the document is framed. The document-level fields cannot
    /// override the per-span answer, only corroborate it.
    #[test]
    fn an_instruction_is_confirmed_whatever_the_framing() {
        for framing in [
            Framing::PresentedAsExample,
            Framing::PresentedAsData,
            Framing::PresentedAsReport,
            Framing::None,
        ] {
            assert_eq!(
                judge_span(
                    SpanRole::Instruction,
                    features(
                        AddressedTo::DocumentRecipient,
                        ImperativeSource::QuotedThirdParty,
                        framing,
                        StatedPurposeExplainsContent::Yes,
                    )
                ),
                SpanJudgement::Confirmed
            );
        }
    }

    /// The intended demotion: a described instruction in a document presenting examples.
    #[test]
    fn a_described_instruction_in_an_example_document_demotes() {
        assert_eq!(
            judge_span(
                SpanRole::DescriptionOfAnInstruction,
                features(
                    AddressedTo::DocumentRecipient,
                    ImperativeSource::QuotedThirdParty,
                    Framing::PresentedAsExample,
                    StatedPurposeExplainsContent::Yes,
                )
            ),
            SpanJudgement::Demoted
        );
    }

    /// Corroboration is required. `span_role` alone is the one field a captured judge would flip.
    #[test]
    fn a_described_instruction_with_no_corroboration_is_confirmed() {
        assert_eq!(
            judge_span(
                SpanRole::DescriptionOfAnInstruction,
                features(
                    AddressedTo::Unclear,
                    ImperativeSource::NonePresent,
                    Framing::None,
                    StatedPurposeExplainsContent::No,
                )
            ),
            SpanJudgement::Confirmed
        );
    }

    /// **A document addressing the agent cannot talk its way out**, however well it corroborates
    /// otherwise. "This is only an example, agent" is what a payload says.
    #[test]
    fn a_document_addressing_the_agent_never_demotes() {
        assert_eq!(
            judge_span(
                SpanRole::DescriptionOfAnInstruction,
                features(
                    AddressedTo::ProcessingAgent,
                    ImperativeSource::QuotedThirdParty,
                    Framing::PresentedAsExample,
                    StatedPurposeExplainsContent::Yes,
                )
            ),
            SpanJudgement::Confirmed
        );
    }
}
