use crate::bench::model::{
    ArtifactDecision, ContextRelation, NativeResponse, NormalizedDecision, NormalizerKind,
    NormalizerManifest, Surface,
};
use crate::Result;

pub fn normalize(
    normalizer: &NormalizerManifest,
    surface: Surface,
    native: &NativeResponse,
    candidate_len: u64,
) -> Result<NormalizedDecision> {
    if normalizer.surface != surface {
        return Err("normalizer surface does not match the case surface".into());
    }
    if native
        .confidence_permille
        .is_some_and(|confidence| confidence > 1000)
    {
        return Err("native confidence_permille exceeds 1000".into());
    }
    if native
        .evidence
        .iter()
        .any(|evidence| evidence.start > evidence.end || evidence.end > candidate_len)
    {
        return Err("native evidence lies outside the candidate bytes".into());
    }
    if native.abstained {
        return Err("an abstained native response cannot be normalized".into());
    }
    match (&normalizer.mapping, surface) {
        (NormalizerKind::PleaseArtifactV1, Surface::ArtifactDetection) => {
            let decision = match native.label.as_str() {
                "detected" => ArtifactDecision::Detected,
                "not_detected" => ArtifactDecision::NotDetected,
                "indeterminate" => ArtifactDecision::Indeterminate,
                _ => return Err("PLEASE native response has an unknown decision label".into()),
            };
            Ok(NormalizedDecision::ArtifactDetection { decision })
        }
        (
            NormalizerKind::NativeV1 {
                positive_labels,
                negative_labels,
            },
            Surface::ArtifactDetection,
        ) => {
            let decision = if positive_labels.contains(&native.label) {
                ArtifactDecision::Detected
            } else if negative_labels.contains(&native.label) {
                ArtifactDecision::NotDetected
            } else if native.label == "indeterminate" {
                ArtifactDecision::Indeterminate
            } else {
                return Err(format!(
                    "native artifact label {:?} has no declared mapping",
                    native.label
                )
                .into());
            };
            Ok(NormalizedDecision::ArtifactDetection { decision })
        }
        (NormalizerKind::NativeV1 { .. }, Surface::ContextualAlignment) => {
            let relation = match native.label.as_str() {
                "aligned_instruction" => ContextRelation::AlignedInstruction,
                "conflicting_instruction" => ContextRelation::ConflictingInstruction,
                "non_instruction" => ContextRelation::NonInstruction,
                "indeterminate" => ContextRelation::Indeterminate,
                _ => {
                    return Err(format!(
                        "native contextual label {:?} is not version-1 vocabulary",
                        native.label
                    )
                    .into())
                }
            };
            Ok(NormalizedDecision::ContextualAlignment { relation })
        }
        _ => Err("normalizer kind is incompatible with the case surface".into()),
    }
}
