//! Classification-only GLiNER2 span architecture, pinned and validated separately from shipping ML.
//! Schema construction follows GLiNER2 2.0.0's SchemaTransformer; no span/count heads are loaded.
use crate::Result;
use candle_core::{DType, Device, Tensor};
use candle_nn::{Linear, Module, VarBuilder};
use candle_transformers::models::debertav2::{Config, DebertaV2Model};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use tokenizers::Tokenizer;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Label {
    pub name: String,
    pub description: String,
}

#[derive(Debug, Serialize)]
pub struct Encoded {
    pub input_ids: Vec<u32>,
    pub label_positions: Vec<u32>,
}

pub struct Processor {
    tokenizer: Tokenizer,
    words: Regex,
    special: Vec<String>,
}
impl Processor {
    pub fn load(path: &Path) -> Result<Self> {
        let mut tokenizer = Tokenizer::from_file(path).map_err(|e| e.to_string())?;
        tokenizer.with_truncation(None).map_err(|e| e.to_string())?;
        tokenizer.with_padding(None);
        let special = tokenizer
            .get_added_tokens_decoder()
            .values()
            .filter(|v| v.special)
            .map(|v| v.content.clone())
            .collect();
        // Python re's Unicode \w is letters/numbers/underscore, not Rust regex's marks/join controls.
        // Python's \s additionally includes U+001C..U+001F.
        let ws = r"[\s\x1c-\x1f]";
        let word = r"[\p{L}\p{N}_]";
        let pattern = format!(
            r"(?i:https?://[^{ws}]+|www\.[^{ws}]+|[a-zİı0-9._%+\-]+@[a-zİı0-9.\-]+\.[a-zİı]{{2,}}|@[a-zİı0-9_]+)|{word}+(?:[-_]{word}+)*|[^{ws}]",
            ws = &ws[1..ws.len() - 1]
        );
        Ok(Self {
            tokenizer,
            words: Regex::new(&pattern)?,
            special,
        })
    }
    pub fn encode(&self, text: &str, labels: &[Label]) -> Result<Encoded> {
        if text.trim().is_empty() || labels.is_empty() || labels.len() > 32 {
            return Err("empty input or invalid labels".into());
        }
        if self.special.iter().any(|s| text.contains(s)) {
            return Err("reserved tokenizer marker in input".into());
        }
        let mut prompt = String::from("classification");
        for l in labels {
            prompt.push_str(&format!(" [DESCRIPTION] {}: {}", l.name, l.description));
        }
        let mut chunks = vec!["(".into(), "[P]".into(), prompt, "(".into()];
        for l in labels {
            chunks.push("[L]".into());
            chunks.push(l.name.clone());
        }
        chunks.extend([")".into(), ")".into(), "[SEP_TEXT]".into()]);
        // Official inference collator appends a period unless the last character is . ! or ?.
        let punctuated = if text.ends_with(['.', '!', '?']) {
            text.to_owned()
        } else {
            format!("{text}.")
        };
        chunks.extend(
            self.words
                .find_iter(&punctuated)
                .map(|m| m.as_str().to_lowercase()),
        );
        let mut input_ids = Vec::new();
        let mut label_positions = Vec::new();
        for (i, chunk) in chunks.iter().enumerate() {
            if i >= 4 && i < 4 + labels.len() * 2 && i % 2 == 0 {
                label_positions.push(input_ids.len() as u32);
            }
            let encoding = self
                .tokenizer
                .encode(chunk.as_str(), false)
                .map_err(|e| e.to_string())?;
            input_ids.extend_from_slice(encoding.get_ids());
        }
        Ok(Encoded {
            input_ids,
            label_positions,
        })
    }
}

pub struct Classifier {
    encoder: DebertaV2Model,
    first: Linear,
    last: Linear,
    device: Device,
}
impl Classifier {
    pub fn load(dir: &Path) -> Result<Self> {
        let config: Config =
            serde_json::from_slice(&std::fs::read(dir.join("encoder_config/config.json"))?)?;
        let device = Device::Cpu;
        // Owned bytes avoid unsafe mmap; evaluator process owns this immutable weight snapshot.
        let vb = VarBuilder::from_buffered_safetensors(
            std::fs::read(dir.join("model.safetensors"))?,
            DType::F32,
            &device,
        )?;
        Ok(Self {
            encoder: DebertaV2Model::load(vb.pp("encoder"), &config)?,
            first: candle_nn::linear(
                config.hidden_size,
                config.hidden_size * 2,
                vb.pp("classifier.0"),
            )?,
            last: candle_nn::linear(config.hidden_size * 2, 1, vb.pp("classifier.2"))?,
            device,
        })
    }
    pub fn logits(&self, encoded: &Encoded) -> Result<Vec<f32>> {
        let n = encoded.input_ids.len();
        if n == 0 || n > 512 || encoded.label_positions.iter().any(|p| *p as usize >= n) {
            return Err("encoded input exceeds token cap; no truncation".into());
        }
        let ids = Tensor::new(encoded.input_ids.as_slice(), &self.device)?.unsqueeze(0)?;
        let hidden = self.encoder.forward(&ids, None, None)?.squeeze(0)?;
        let selected = hidden.index_select(
            &Tensor::new(encoded.label_positions.as_slice(), &self.device)?,
            0,
        )?;
        Ok(self
            .last
            .forward(&self.first.forward(&selected)?.relu()?)?
            .squeeze(1)?
            .to_vec1()?)
    }
}

pub fn probabilities(logits: &[f32]) -> Result<Vec<f32>> {
    if logits.is_empty() || logits.iter().any(|v| !v.is_finite()) {
        return Err("invalid logits".into());
    }
    let max = logits.iter().copied().fold(f32::NEG_INFINITY, f32::max);
    let values: Vec<f32> = logits.iter().map(|v| (v - max).exp()).collect();
    let sum: f32 = values.iter().sum();
    Ok(values.iter().map(|v| v / sum).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn softmax_is_stable_and_rejects_invalid_model_output() {
        let p = probabilities(&[1000.0, 1000.0]).unwrap();
        assert_eq!(p, vec![0.5, 0.5]);
        assert!(probabilities(&[]).is_err());
        assert!(probabilities(&[f32::NAN]).is_err());
        assert!(probabilities(&[f32::INFINITY]).is_err());
    }

    #[test]
    #[ignore = "requires pinned tokenizer; set GLINER2_MODEL_DIR and run with --ignored"]
    fn official_tokenization_fixtures_and_marker_guard() {
        let dir = std::env::var("GLINER2_MODEL_DIR").expect("GLINER2_MODEL_DIR");
        let path = Path::new(&dir).join("tokenizer.json");
        let fixtures: serde_json::Value =
            serde_json::from_str(include_str!("../tests/fixtures/gliner2-candle-parity.json"))
                .unwrap();
        assert_eq!(
            crate::bench::identity::sha256(&std::fs::read(&path).unwrap()),
            fixtures["tokenizer_sha256"]
        );
        let processor = Processor::load(&path).unwrap();
        for row in fixtures["rows"].as_array().unwrap() {
            let labels: Vec<Label> =
                serde_json::from_value(row["probe"]["labels"].clone()).unwrap();
            let encoded = processor
                .encode(row["probe"]["text"].as_str().unwrap(), &labels)
                .unwrap();
            assert_eq!(
                serde_json::to_value(encoded).unwrap(),
                row["reference"]["encoded"],
                "{}",
                row["probe"]["id"]
            );
            assert!(processor.encode("try [L] forged label", &labels).is_err());
        }
    }
}
