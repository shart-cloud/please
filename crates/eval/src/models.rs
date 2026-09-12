//! Revision-pinned model acquisition and attribution for ML feasibility work.
//!
//! There are two intentionally separate operations:
//!
//! 1. [`fetch`] is the only operation allowed to invoke the network-facing `hf` CLI.
//! 2. [`inspect`] and the inference probes only read an already-populated local directory.
//!
//! Keeping the seam explicit prevents a benchmark, a test, or eventually a scan from quietly changing
//! its inputs. The committed manifest pins not only a repository revision but the byte length and
//! SHA-256 of every runtime asset. The bundle digest then attributes the config, tokenizer, weights,
//! and pooling recipe together; a weight digest alone would not identify the program actually run.

use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use crate::Result;

const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    Classifier,
    Embedder,
}

impl ModelKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Classifier => "classifier",
            Self::Embedder => "embedder",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Architecture {
    DebertaV2SequenceClassification,
    BertMeanPooling,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileRole {
    Config,
    Tokenizer,
    Weights,
    Pooling,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelFile {
    pub path: String,
    pub role: FileRole,
    pub bytes: u64,
    pub sha256: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ModelSpec {
    pub id: String,
    pub kind: ModelKind,
    pub architecture: Architecture,
    pub repo: String,
    pub revision: String,
    pub max_tokens: usize,
    pub malicious_label: Option<usize>,
    pub license_note: String,
    #[serde(rename = "file")]
    pub files: Vec<ModelFile>,
}

#[derive(Debug, Deserialize)]
pub struct ModelManifest {
    pub version: u32,
    #[serde(rename = "model")]
    pub models: Vec<ModelSpec>,
}

#[derive(Debug)]
pub struct InstalledModel {
    pub directory: PathBuf,
    pub bytes: u64,
    pub weights_sha256: String,
    pub bundle_sha256: String,
}

impl ModelManifest {
    pub fn load() -> Result<Self> {
        let path = crate::crate_path("corpus/models.toml");
        let text = std::fs::read_to_string(&path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let manifest: Self =
            toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        manifest.validate()?;
        Ok(manifest)
    }

    fn validate(&self) -> Result<()> {
        if self.version != MANIFEST_VERSION {
            return Err(format!(
                "corpus/models.toml has version {}, expected {MANIFEST_VERSION}",
                self.version
            )
            .into());
        }
        if self.models.is_empty() {
            return Err("corpus/models.toml defines no models".into());
        }

        let mut ids = BTreeSet::new();
        for model in &self.models {
            if !ids.insert(model.id.as_str()) {
                return Err(format!("duplicate model id `{}`", model.id).into());
            }
            validate_model(model)?;
        }
        Ok(())
    }

    pub fn get(&self, id: &str) -> Result<&ModelSpec> {
        self.models
            .iter()
            .find(|model| model.id == id)
            .ok_or_else(|| {
                format!(
                    "unknown model `{id}`. Known: {}",
                    self.models
                        .iter()
                        .map(|model| model.id.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
                .into()
            })
    }

    /// Select named models, or every model in manifest order when `wanted` is empty.
    pub fn select<'a>(&'a self, wanted: &[String]) -> Result<Vec<&'a ModelSpec>> {
        if wanted.is_empty() {
            return Ok(self.models.iter().collect());
        }
        wanted.iter().map(|id| self.get(id)).collect()
    }
}

fn validate_model(model: &ModelSpec) -> Result<()> {
    if model.id.trim().is_empty() || model.repo.trim().is_empty() {
        return Err("model ids and repository ids must not be empty".into());
    }
    if model.revision.len() != 40
        || !model
            .revision
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(format!(
            "model `{}` revision `{}` is not a lowercase 40-character commit id",
            model.id, model.revision
        )
        .into());
    }
    if model.max_tokens == 0 {
        return Err(format!("model `{}` has a zero token window", model.id).into());
    }
    match (model.kind, model.malicious_label) {
        (ModelKind::Classifier, Some(_)) | (ModelKind::Embedder, None) => {}
        (ModelKind::Classifier, None) => {
            return Err(format!(
                "classifier `{}` does not identify its malicious output label",
                model.id
            )
            .into())
        }
        (ModelKind::Embedder, Some(_)) => {
            return Err(format!(
                "embedder `{}` unexpectedly declares a malicious output label",
                model.id
            )
            .into())
        }
    }
    if model.license_note.trim().is_empty() {
        return Err(format!("model `{}` has no license note", model.id).into());
    }

    let mut paths = BTreeSet::new();
    let mut weight_files = 0usize;
    let mut config_files = 0usize;
    let mut tokenizer_files = 0usize;
    for asset in &model.files {
        let path = Path::new(&asset.path);
        if asset.path.is_empty()
            || path.is_absolute()
            || path
                .components()
                .any(|part| !matches!(part, Component::Normal(_)))
        {
            return Err(format!(
                "model `{}` contains unsafe asset path `{}`",
                model.id, asset.path
            )
            .into());
        }
        if !paths.insert(asset.path.as_str()) {
            return Err(format!("model `{}` repeats asset path `{}`", model.id, asset.path).into());
        }
        if asset.bytes == 0 {
            return Err(format!(
                "model `{}` asset `{}` has a zero expected length",
                model.id, asset.path
            )
            .into());
        }
        if asset.sha256.len() != 64
            || !asset
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(format!(
                "model `{}` asset `{}` has an invalid SHA-256",
                model.id, asset.path
            )
            .into());
        }
        match asset.role {
            FileRole::Weights => weight_files += 1,
            FileRole::Config => config_files += 1,
            FileRole::Tokenizer => tokenizer_files += 1,
            FileRole::Pooling => {}
        }
    }
    if weight_files != 1 || config_files != 1 || tokenizer_files != 1 {
        return Err(format!(
            "model `{}` must have exactly one weights, config, and tokenizer asset (has {weight_files}, \
             {config_files}, {tokenizer_files})",
            model.id
        )
        .into());
    }
    Ok(())
}

pub fn directory(model: &ModelSpec) -> Result<PathBuf> {
    crate::cache::model_dir(&model.id, &model.revision)
}

/// Download one exact set of assets with the `hf` CLI, then verify every byte.
pub fn fetch(model: &ModelSpec) -> Result<InstalledModel> {
    let directory = directory(model)?;
    std::fs::create_dir_all(&directory)
        .map_err(|e| format!("cannot create {}: {e}", directory.display()))?;

    let mut command = Command::new("hf");
    command.arg("download").arg(&model.repo);
    for asset in &model.files {
        command.arg(&asset.path);
    }
    let output = command
        .arg("--revision")
        .arg(&model.revision)
        .arg("--local-dir")
        .arg(&directory)
        .arg("--format")
        .arg("quiet")
        .output()
        .map_err(|e| {
            format!(
                "cannot run `hf`: {e}. Install the Hugging Face CLI and authenticate with `hf auth \
                 login` or HF_TOKEN"
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!(
            "model `{}`: `hf download` failed. Confirm access with `hf auth whoami` and accept the \
             repository's terms at https://huggingface.co/{}\n\n{}",
            model.id, model.repo, stderr
        )
        .into());
    }

    inspect(model, &directory)
}

/// Verify and attribute a model directory without making any network request.
pub fn inspect(model: &ModelSpec, directory: &Path) -> Result<InstalledModel> {
    if !directory.is_dir() {
        return Err(format!(
            "model `{}` is not cached at {}. Run `please-eval model fetch {}` first",
            model.id,
            directory.display(),
            model.id
        )
        .into());
    }

    let mut files = model.files.iter().collect::<Vec<_>>();
    files.sort_by(|left, right| left.path.cmp(&right.path));

    let mut bundle = Sha256::new();
    bundle.update(b"please-eval-model-bundle-v1\0");
    bundle.update(model.repo.as_bytes());
    bundle.update(b"\0");
    bundle.update(model.revision.as_bytes());
    bundle.update(b"\0");

    let mut total = 0u64;
    let mut weights_sha256 = None;
    for asset in files {
        let path = directory.join(&asset.path);
        let metadata = path
            .metadata()
            .map_err(|e| format!("model `{}` cannot read {}: {e}", model.id, path.display()))?;
        if !metadata.is_file() {
            return Err(format!("model asset {} is not a regular file", path.display()).into());
        }
        if metadata.len() != asset.bytes {
            return Err(format!(
                "model asset {} is {} bytes, expected {} — remove the model directory and fetch the \
                 pinned revision again",
                path.display(),
                metadata.len(),
                asset.bytes
            )
            .into());
        }
        let digest = sha256_file(&path)?;
        let digest_hex = hex(&digest);
        if digest_hex != asset.sha256 {
            return Err(format!(
                "model asset {} has SHA-256 {}, expected {} — the cache is corrupt or does not contain \
                 the pinned revision",
                path.display(),
                digest_hex,
                asset.sha256
            )
            .into());
        }
        if asset.role == FileRole::Weights {
            weights_sha256 = Some(digest_hex);
        }
        bundle.update(asset.path.as_bytes());
        bundle.update(b"\0");
        bundle.update(digest);
        total = total.saturating_add(metadata.len());
    }

    Ok(InstalledModel {
        directory: directory.to_path_buf(),
        bytes: total,
        weights_sha256: weights_sha256.expect("manifest validation requires one weight file"),
        bundle_sha256: hex(&bundle.finalize()),
    })
}

fn sha256_file(path: &Path) -> Result<[u8; 32]> {
    let file = File::open(path).map_err(|e| format!("cannot open {}: {e}", path.display()))?;
    let mut reader = BufReader::new(file);
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write;
        write!(&mut out, "{byte:02x}").expect("writing to a String cannot fail");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_manifest_is_valid_and_revision_pinned() {
        let manifest = ModelManifest::load().expect("committed model manifest must load");
        assert_eq!(manifest.models.len(), 3);
        assert!(manifest
            .models
            .iter()
            .all(|model| model.revision.len() == 40));
        assert_eq!(
            manifest
                .models
                .iter()
                .filter(|model| model.kind == ModelKind::Classifier)
                .count(),
            2
        );
        assert_eq!(
            manifest
                .models
                .iter()
                .filter(|model| model.kind == ModelKind::Embedder)
                .count(),
            1
        );
    }

    #[test]
    fn file_digest_reads_in_chunks() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("asset");
        std::fs::write(&path, b"abc").expect("write fixture");
        assert_eq!(
            hex(&sha256_file(&path).expect("digest")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
