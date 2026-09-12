//! Resolve caller-owned local configuration; inference and evidence composition live in please-ml.

use std::path::{Path, PathBuf};

use please_ml::{Architecture, MlConfig, MlLoadResult, MlModel, ModelKind};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Config {
    model_path: PathBuf,
    model_id: String,
    revision: String,
    max_tokens: usize,
    malicious_label: usize,
    threshold: u16,
    #[serde(default)]
    windowing: please_ml::config::WindowSettings,
}

pub fn load(path: &Path) -> Result<MlLoadResult, String> {
    let bytes = std::fs::read(path).map_err(|e| e.to_string())?;
    let config: Config = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    if config.model_id.trim().is_empty() || config.revision.trim().is_empty() {
        return Err("model_id and revision must not be empty".into());
    }
    let config = MlConfig {
        model_path: path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(config.model_path),
        model_id: config.model_id,
        revision: config.revision,
        kind: ModelKind::Classifier,
        architecture: Architecture::DebertaV2SequenceClassification,
        max_tokens: config.max_tokens,
        windowing: config.windowing,
        malicious_label: Some(config.malicious_label),
        threshold: config.threshold,
    };
    config.validate()?;
    Ok(MlModel::load(config))
}
