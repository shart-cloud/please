//! The Candle inference backend.
//!
//! Ported from `crates/eval/src/ml.rs`, which is where T002, T003 and T004 measured these exact paths
//! against real weights. Two things changed on the way in, and both are requirements the feasibility runs
//! did not have to meet: long inputs are chunked rather than truncated (FR-612), and nothing returns a
//! `Result` to a caller who could ignore it.
//!
//! The eval copy stays where it is. It is the instrument, it measures models this crate does not ship, and
//! a research harness that imports the production crate can no longer answer "is the production crate
//! right?" — which is the question it exists to answer.

use super::{to_permille, Outcome};
use crate::config::{Architecture, MlConfig, ModelKind};
use candle_core::{DType, Device, Tensor};
use candle_nn::VarBuilder;
use candle_transformers::models::{bert, debertav2};
use std::collections::HashMap;
use tokenizers::{Tokenizer, TruncationParams};

pub(super) enum Backend {
    Classifier {
        model: Box<debertav2::DebertaV2SeqClassificationModel>,
        tokenizer: Tokenizer,
        malicious_label: usize,
        device: Device,
    },
    Embedder {
        model: Box<bert::BertModel>,
        tokenizer: Tokenizer,
        device: Device,
    },
}

impl Backend {
    pub(super) fn load(config: &MlConfig) -> Result<Self, String> {
        let directory = &config.model_path;
        let config_path = directory.join("config.json");
        let tokenizer_path = directory.join("tokenizer.json");
        let weights_path = directory.join("model.safetensors");

        let config_bytes = std::fs::read(&config_path)
            .map_err(|e| format!("cannot read {}: {e}", config_path.display()))?;
        let mut tokenizer = Tokenizer::from_file(&tokenizer_path)
            .map_err(|e| format!("cannot load {}: {e}", tokenizer_path.display()))?;

        // Do not inherit padding or truncation serialised by somebody's training script. A single
        // sequence needs no padding, and truncation is handled explicitly by the chunker below —
        // inheriting it here would silently drop the tail of every long input, which is precisely the
        // behaviour FR-612 exists to prevent.
        tokenizer.with_padding(None);
        tokenizer
            .with_truncation(None)
            .map_err(|e| format!("cannot configure tokenizer for `{}`: {e}", config.model_id))?;

        let device = Device::Cpu;
        // SAFETY: `VarBuilder` keeps the mapping alive for as long as any tensor can refer to it, and the
        // model directory is not written during a scan. The alternative allocates a second full copy of
        // the weights — 1.08 GiB for Prompt Guard 2, measured in T003.
        //
        // This call is why the crate does not carry `#![forbid(unsafe_code)]`, and why it is a separate
        // crate rather than a module in core.
        let weights =
            unsafe { VarBuilder::from_mmaped_safetensors(&[&weights_path], DType::F32, &device) }
                .map_err(|e| format!("cannot map weights for `{}`: {e}", config.model_id))?;

        match (config.kind, config.architecture) {
            (ModelKind::Classifier, Architecture::DebertaV2SequenceClassification) => {
                let parsed: debertav2::Config = serde_json::from_slice(&config_bytes)
                    .map_err(|e| format!("cannot parse {}: {e}", config_path.display()))?;
                let malicious_label = config
                    .malicious_label
                    .ok_or_else(|| "classifier names no malicious label".to_string())?;

                // T002 measured a shipping model whose `config.json` omits `id2label` entirely. Candle
                // needs *a* mapping to construct the head, so synthesise one from the label index the
                // caller supplied rather than failing on a field that carries no information we need.
                let labels = if parsed.id2label.is_none() {
                    let benign = usize::from(malicious_label == 0);
                    Some(HashMap::from([
                        (benign as u32, "BENIGN".to_string()),
                        (malicious_label as u32, "MALICIOUS".to_string()),
                    ]))
                } else {
                    None
                };

                let model = debertav2::DebertaV2SeqClassificationModel::load(
                    weights.pp("deberta"),
                    &parsed,
                    labels,
                )
                .map_err(|e| {
                    format!(
                        "cannot construct `{}` as DeBERTa-v2: {e}",
                        config.model_id
                    )
                })?;
                Ok(Backend::Classifier {
                    model: Box::new(model),
                    tokenizer,
                    malicious_label,
                    device,
                })
            }
            (ModelKind::Embedder, Architecture::BertMeanPooling) => {
                let parsed: bert::Config = serde_json::from_slice(&config_bytes)
                    .map_err(|e| format!("cannot parse {}: {e}", config_path.display()))?;
                let model = bert::BertModel::load(weights, &parsed)
                    .map_err(|e| format!("cannot construct `{}` as BERT: {e}", config.model_id))?;
                Ok(Backend::Embedder {
                    model: Box::new(model),
                    tokenizer,
                    device,
                })
            }
            _ => Err(format!(
                "model `{}` pairs an incompatible kind and architecture",
                config.model_id
            )),
        }
    }

    /// Classify, chunking at the context window and keeping the maximum (FR-612).
    pub(super) fn classify(&self, config: &MlConfig, text: &str) -> Outcome<u16> {
        let Backend::Classifier {
            model,
            tokenizer,
            malicious_label,
            device,
        } = self
        else {
            return Outcome::NotApplicable;
        };

        let encoded = match tokenizer.encode(text, true) {
            Ok(encoded) => encoded,
            Err(e) => return Outcome::Failed(format!("tokenization failed: {e}")),
        };

        // Two special tokens bracket every chunk, so the usable payload is the window minus those. Getting
        // this wrong produces a tensor one or two positions too long and an error from the model rather
        // than a wrong answer, but the error would be per-document and mystifying.
        let window = config.max_tokens.saturating_sub(2).max(1);
        let ids = encoded.get_ids();
        let type_ids = encoded.get_type_ids();
        let mask = encoded.get_attention_mask();

        if ids.is_empty() {
            // Whitespace, or text the tokenizer reduced to nothing. Not a failure and not a finding.
            return Outcome::Ok(0);
        }

        let mut highest: u16 = 0;
        for start in (0..ids.len()).step_by(window) {
            let end = (start + window).min(ids.len());
            let probability = match forward_classifier(
                model,
                device,
                *malicious_label,
                &ids[start..end],
                &type_ids[start..end],
                &mask[start..end],
            ) {
                Ok(probability) => probability,
                Err(detail) => return Outcome::Failed(detail),
            };
            let permille = match to_permille(probability) {
                Ok(permille) => permille,
                Err(detail) => return Outcome::Failed(detail),
            };
            // Max, not mean. A megabyte of legitimate prose around one hostile paragraph must not average
            // that paragraph away — dilution is the attack, not an edge case.
            highest = highest.max(permille);
        }
        Outcome::Ok(highest)
    }

    pub(super) fn embed(&self, config: &MlConfig, text: &str) -> Outcome<Vec<f32>> {
        let Backend::Embedder {
            model,
            tokenizer,
            device,
        } = self
        else {
            return Outcome::NotApplicable;
        };

        // Embedding truncates where classification chunks, and the asymmetry is deliberate. A pooled
        // vector for a segment longer than the window has no defined meaning — averaging several chunk
        // vectors produces a point that represents none of them — whereas a classifier's per-chunk
        // probabilities combine under a maximum with a clear reading. Segments are paragraphs; one longer
        // than 512 tokens is rare, and the truncation is recorded by the caller as coverage, not hidden.
        let mut tokenizer = tokenizer.clone();
        if tokenizer
            .with_truncation(Some(TruncationParams {
                max_length: config.max_tokens,
                ..Default::default()
            }))
            .is_err()
        {
            return Outcome::Failed("cannot configure truncation".to_string());
        }

        let encoded = match tokenizer.encode(text, true) {
            Ok(encoded) => encoded,
            Err(e) => return Outcome::Failed(format!("tokenization failed: {e}")),
        };
        if encoded.get_ids().is_empty() {
            return Outcome::Failed("nothing to embed".to_string());
        }

        match forward_embedder(
            model,
            device,
            encoded.get_ids(),
            encoded.get_type_ids(),
            encoded.get_attention_mask(),
        ) {
            Ok(vector) => Outcome::Ok(vector),
            Err(detail) => Outcome::Failed(detail),
        }
    }
}

fn forward_classifier(
    model: &debertav2::DebertaV2SeqClassificationModel,
    device: &Device,
    malicious_label: usize,
    ids: &[u32],
    type_ids: &[u32],
    mask: &[u32],
) -> Result<f32, String> {
    let build = || -> Result<f32, candle_core::Error> {
        let input_ids = Tensor::new(ids, device)?.unsqueeze(0)?;
        let token_type_ids = Tensor::new(type_ids, device)?.unsqueeze(0)?;
        let attention_mask = Tensor::new(mask, device)?.unsqueeze(0)?;
        let logits = model.forward(&input_ids, Some(token_type_ids), Some(attention_mask))?;
        let probabilities = candle_nn::ops::softmax_last_dim(&logits)?.to_vec2::<f32>()?;
        let row = probabilities
            .first()
            .ok_or_else(|| candle_core::Error::Msg("classifier returned no rows".into()))?;
        row.get(malicious_label).copied().ok_or_else(|| {
            candle_core::Error::Msg(format!(
                "classifier returned {} labels, but the malicious label is {malicious_label}",
                row.len()
            ))
        })
    };
    build().map_err(|e| format!("classifier inference failed: {e}"))
}

fn forward_embedder(
    model: &bert::BertModel,
    device: &Device,
    ids: &[u32],
    type_ids: &[u32],
    mask: &[u32],
) -> Result<Vec<f32>, String> {
    let build = || -> Result<Vec<f32>, candle_core::Error> {
        let input_ids = Tensor::new(ids, device)?.unsqueeze(0)?;
        let token_type_ids = Tensor::new(type_ids, device)?.unsqueeze(0)?;
        let attention_mask = Tensor::new(mask, device)?.unsqueeze(0)?;
        let hidden = model.forward(&input_ids, &token_type_ids, Some(&attention_mask))?;

        // Sentence Transformers' all-MiniLM-L6-v2 recipe: mask-aware mean pooling, then L2
        // normalisation. Averaging padding into the vector is the common error here, and it makes
        // similarity measure tokenizer padding rather than semantics.
        let mask_f = attention_mask.to_dtype(DType::F32)?.unsqueeze(2)?;
        let summed = hidden.broadcast_mul(&mask_f)?.sum(1)?;
        let count = mask_f.sum(1)?.clamp(1e-9f32, f32::MAX)?;
        let pooled = summed.broadcast_div(&count)?;
        let norm = pooled.sqr()?.sum_keepdim(1)?.sqrt()?;
        pooled.broadcast_div(&norm)?.squeeze(0)?.to_vec1::<f32>()
    };
    let vector = build().map_err(|e| format!("embedder inference failed: {e}"))?;
    if vector.iter().any(|value| !value.is_finite()) {
        return Err("embedder returned a non-finite vector".to_string());
    }
    Ok(vector)
}
