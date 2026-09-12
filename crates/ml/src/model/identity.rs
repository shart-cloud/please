use crate::config::MlConfig;
use please_core::inference::InferenceIdentity;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(super) fn identity(
    config: &MlConfig,
    weights: &[u8],
    tokenizer: &[u8],
    model_config: &[u8],
) -> InferenceIdentity {
    let mut fields = BTreeMap::new();
    for (key, bytes) in [
        ("weights_sha256", weights),
        ("tokenizer_sha256", tokenizer),
        ("config_sha256", model_config),
    ] {
        fields.insert(key.into(), format!("{:x}", Sha256::digest(bytes)));
    }
    for (key, value) in [
        ("build_sha256", env!("PLEASE_INFERENCE_BUILD").to_string()),
        ("architecture", match config.architecture { crate::Architecture::DebertaV2SequenceClassification => "deberta-v2-sequence-classification", crate::Architecture::BertMeanPooling => "bert-mean-pooling" }.into()),
        ("kind", match config.kind { crate::ModelKind::Classifier => "classifier", crate::ModelKind::Embedder => "embedder" }.into()),
        ("malicious_label", config.malicious_label.map_or("none".into(), |v| v.to_string())),
        ("max_tokens", config.max_tokens.to_string()),
        ("overlap_tokens", config.windowing.overlap_tokens.to_string()),
        ("recipe", match config.kind {
            crate::ModelKind::Classifier => "payload-windows-v1;postprocess-each;no-padding;no-inherited-truncation;max;round-permille;uncalibrated",
            crate::ModelKind::Embedder => "native-truncate;no-padding;attention-mask-mean;l2-normalize",
        }.into()),
        ("backend", "candle;cpu;f32".into()),
    ] { fields.insert(key.into(), value); }
    InferenceIdentity::new(fields)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn identity_tracks_inference_but_not_paths_thresholds_or_budgets() {
        let mut config = super::super::tests::classifier_config("a".into());
        let base = identity(&config, b"w", b"t", b"c");
        for bytes in [(b"x", b"t", b"c"), (b"w", b"x", b"c"), (b"w", b"t", b"x")] {
            assert_ne!(base, identity(&config, bytes.0, bytes.1, bytes.2));
        }
        config.model_path = "b".into();
        config.threshold += 1;
        config.windowing.max_windows += 1;
        assert_eq!(base, identity(&config, b"w", b"t", b"c"));
        config.max_tokens += 1;
        assert_ne!(base, identity(&config, b"w", b"t", b"c"));
        config.max_tokens -= 1;
        config.malicious_label = Some(0);
        assert_ne!(base, identity(&config, b"w", b"t", b"c"));
        config.malicious_label = Some(1);
        config.windowing.overlap_tokens = 1;
        assert_ne!(base, identity(&config, b"w", b"t", b"c"));
    }
}
