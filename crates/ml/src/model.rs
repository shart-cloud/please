//! Loading weights, and the two questions a loaded model can answer.
//!
//! # Why loading is infallible from the caller's side
//!
//! [`MlModel::load`] returns an [`MlLoadResult`], not a `Result`. The reasoning is the one
//! `Engine::builtin` and `Judge::new` already gave: an `Err` in a caller's control flow is one
//! `unwrap_or_default` away from a silent skip, and a silently skipped detection tier is a fail-open. An
//! [`MlLoadResult::Unavailable`] cannot be collapsed into "clean" by accident — the caller has to name it,
//! and the only useful thing to do with it is record a `TierUnavailable` gap.
//!
//! # Why inference never panics
//!
//! A malformed tensor shape, a tokenizer that produces zero tokens, a NaN in a softmax — these are
//! properties of *attacker-supplied text* meeting a model, and a scanner that aborts on one is a scanner
//! an attacker can turn off with a crafted document. Every inference path here returns a value and records
//! the failure; none of them unwrap.

use crate::config::{MlConfig, ModelKind};
use sha2::{Digest, Sha256};
use std::path::Path;

/// The outcome of a load attempt. **The only failure path** (contracts/ml-tier.md).
pub enum MlLoadResult {
    Loaded(Box<MlModel>),
    /// The model could not be loaded, with a human-readable cause.
    ///
    /// The caller MUST NOT treat this as `Clean`. It becomes a `CoverageGap` with
    /// `IncompleteCause::TierUnavailable`, which degrades the verdict to `Inconclusive` unless structural
    /// findings already made it `RiskFound`.
    Unavailable(String),
}

impl MlLoadResult {
    /// The loaded model, or `None`. Convenience for callers that have already recorded the gap.
    pub fn ok(self) -> Option<Box<MlModel>> {
        match self {
            Self::Loaded(model) => Some(model),
            Self::Unavailable(_) => None,
        }
    }

    pub fn unavailable_detail(&self) -> Option<&str> {
        match self {
            Self::Loaded(_) => None,
            Self::Unavailable(detail) => Some(detail),
        }
    }
}

/// A loaded model, ready to answer one of two questions.
///
/// `Send + Sync` is a contract requirement, not an accident: one loaded model serves a whole directory
/// walk, and re-loading Prompt Guard 2 per target would cost T005's measured 2.3 s each time. Candle's
/// `Tensor` has no interior mutability and no thread-local state, and `tokenizers::Tokenizer` is likewise
/// `Send + Sync`, so the property holds without a lock.
pub struct MlModel {
    config: MlConfig,
    digest: String,
    backend: Backend,
}

impl MlModel {
    /// Load a model from the directory `config.model_path` names.
    ///
    /// Expects `config.json`, `tokenizer.json`, and `model.safetensors` beside one another — the layout
    /// a Hugging Face snapshot already has, so `please-eval model fetch` produces it without a step.
    pub fn load(config: MlConfig) -> MlLoadResult {
        if let Err(detail) = config.validate() {
            return MlLoadResult::Unavailable(detail);
        }

        let weights_path = config.model_path.join("model.safetensors");
        let digest = match digest_of(&weights_path) {
            Ok(digest) => digest,
            Err(detail) => return MlLoadResult::Unavailable(detail),
        };

        match Backend::load(&config) {
            Ok(backend) => MlLoadResult::Loaded(Box::new(MlModel {
                config,
                digest,
                backend,
            })),
            Err(detail) => MlLoadResult::Unavailable(detail),
        }
    }

    pub fn config(&self) -> &MlConfig {
        &self.config
    }

    /// SHA-256 over `model.safetensors` as it sits on disk.
    ///
    /// Computed at load rather than trusted from a manifest, because a manifest records what was
    /// *downloaded* and this records what was *loaded*. Between the two sit a mirror, a cache, and a
    /// filesystem, and the verdict should attribute to the bytes that produced it.
    pub fn digest(&self) -> &str {
        &self.digest
    }

    /// Classify a text segment, returning per-mille probability of the malicious class.
    ///
    /// `None` when this model is an embedder. An inference failure also yields `None` with a detail —
    /// never `Some(0)`, which would be indistinguishable from a confident verdict of benign.
    ///
    /// Long inputs are chunked at the context window with **max-score pooling**: the returned probability
    /// is the highest any chunk reached. This is Meta's documented recommendation for Prompt Guard 2, and
    /// the alternative — mean pooling — would let a long benign document dilute a short payload below any
    /// threshold, which is the exact attack the tier exists to catch.
    pub fn classify(&self, text: &str) -> Outcome<u16> {
        if self.config.kind != ModelKind::Classifier {
            return Outcome::NotApplicable;
        }
        self.backend.classify(&self.config, text)
    }

    /// Embed a text segment into a normalised vector.
    ///
    /// `None` when this model is a classifier. Unlike `classify`, a failure here returns
    /// `Outcome::Failed`: a zero vector would be a *valid-looking* input to cosine similarity and would
    /// quietly score as maximally unlike everything, manufacturing an outlier out of an error.
    pub fn embed(&self, text: &str) -> Outcome<Vec<f32>> {
        if self.config.kind != ModelKind::Embedder {
            return Outcome::NotApplicable;
        }
        self.backend.embed(&self.config, text)
    }
}

/// What one inference call produced.
///
/// Three arms rather than `Option`, because "this model does not do that" and "this model tried and
/// failed" send a caller to different places: the first is a configuration answer and records nothing,
/// the second is a coverage gap.
#[derive(Debug, Clone, PartialEq)]
pub enum Outcome<T> {
    Ok(T),
    /// The wrong half of the tier was asked — a classifier asked to embed, or the reverse.
    NotApplicable,
    /// Inference was attempted and did not produce a usable answer.
    Failed(String),
}

impl<T> Outcome<T> {
    pub fn ok(self) -> Option<T> {
        match self {
            Self::Ok(value) => Some(value),
            _ => None,
        }
    }

    pub fn failure(&self) -> Option<&str> {
        match self {
            Self::Failed(detail) => Some(detail),
            _ => None,
        }
    }
}

/// SHA-256 of a file, streamed.
///
/// Streamed rather than read whole because Prompt Guard 2's weights are 1.08 GiB and this runs before the
/// memory map that would otherwise be the peak allocation.
fn digest_of(path: &Path) -> Result<String, String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path)
        .map_err(|e| format!("cannot open weights at {}: {e}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|e| format!("cannot read weights at {}: {e}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

/// Convert a probability in `[0.0, 1.0]` to per-mille, refusing anything outside it.
///
/// The range check is not paranoia about softmax. It is the guard against a `malicious_label` pointing
/// past the end of the logits row, a NaN propagated from a malformed weight, and an f32 that overflowed —
/// each of which would otherwise become a plausible-looking score.
///
/// Unused in a build without the `candle` feature — there is no inference to convert the output of — but
/// still compiled and still tested, which is the point of allowing it rather than gating it: the guard is
/// pure arithmetic, and a backend-less build that could not test it would be a build that silently stopped
/// covering the range check.
#[cfg_attr(not(feature = "candle"), allow(dead_code))]
pub(crate) fn to_permille(probability: f32) -> Result<u16, String> {
    if !probability.is_finite() || !(0.0..=1.0).contains(&probability) {
        return Err(format!("classifier returned invalid probability {probability}"));
    }
    Ok((probability * 1000.0).round() as u16)
}

// ── The backend ─────────────────────────────────────────────────────────────────────────────────
//
// Two implementations of the same private surface. With `candle` off the crate still compiles, still
// exposes every type, and still runs every unit test that does not need weights — the outlier
// arithmetic, the observation builder, the config validation. What it cannot do is infer, and it says so
// through the ordinary `Unavailable` path rather than through a missing symbol.

#[cfg(not(feature = "candle"))]
struct Backend;

#[cfg(not(feature = "candle"))]
impl Backend {
    fn load(_config: &MlConfig) -> Result<Self, String> {
        Err("this build has no inference backend; rebuild with --features candle".to_string())
    }

    fn classify(&self, _config: &MlConfig, _text: &str) -> Outcome<u16> {
        Outcome::Failed("no inference backend".to_string())
    }

    fn embed(&self, _config: &MlConfig, _text: &str) -> Outcome<Vec<f32>> {
        Outcome::Failed("no inference backend".to_string())
    }
}

#[cfg(feature = "candle")]
mod candle_backend;

#[cfg(feature = "candle")]
use candle_backend::Backend;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Architecture;
    use std::path::PathBuf;

    fn classifier_config(path: PathBuf) -> MlConfig {
        MlConfig {
            model_path: path,
            model_id: "test-classifier".to_string(),
            revision: "abcdef".to_string(),
            kind: ModelKind::Classifier,
            architecture: Architecture::DebertaV2SequenceClassification,
            max_tokens: 512,
            malicious_label: Some(1),
            threshold: 700,
        }
    }

    // ── The range guard on the way out of a softmax ─────────────────────────────────────────────
    //
    // Worth testing directly rather than only through inference, because the values it rejects do not
    // arrive from a well-behaved model. They arrive from a `malicious_label` pointing past the end of a
    // logits row, or a NaN propagated out of a malformed weight — and each would otherwise become a
    // plausible-looking score rather than an error.

    #[test]
    fn probabilities_convert_to_permille() {
        assert_eq!(to_permille(0.0), Ok(0));
        assert_eq!(to_permille(1.0), Ok(1000));
        assert_eq!(to_permille(0.7), Ok(700));
        // 0.3882 — T002's measured benign ceiling on ProtectAI, and the reason no threshold below ~400 is
        // available on that model.
        assert_eq!(to_permille(0.3882), Ok(388));
    }

    #[test]
    fn a_non_probability_is_refused_rather_than_rounded() {
        assert!(to_permille(f32::NAN).is_err());
        assert!(to_permille(f32::INFINITY).is_err());
        assert!(to_permille(-0.1).is_err());
        assert!(to_permille(1.1).is_err());
    }

    // ── Loading refuses before it reads ─────────────────────────────────────────────────────────

    #[test]
    fn a_missing_directory_is_unavailable_not_a_panic() {
        let result = MlModel::load(classifier_config(PathBuf::from("/nonexistent/model")));
        assert!(result.unavailable_detail().is_some());
    }

    #[test]
    fn a_classifier_without_a_malicious_label_is_refused_before_any_io() {
        // Validation runs first, so this fails on the configuration rather than on the missing weights —
        // and the message says which. A run rejected here costs nothing; the same rejection after a
        // 2.3 s load costs 2.3 s (T003).
        let mut config = classifier_config(PathBuf::from("/nonexistent/model"));
        config.malicious_label = None;
        let detail = MlModel::load(config)
            .unavailable_detail()
            .expect("refused")
            .to_string();
        assert!(detail.contains("malicious label"), "got: {detail}");
    }

    #[test]
    fn an_out_of_range_threshold_is_refused() {
        let mut config = classifier_config(PathBuf::from("/nonexistent/model"));
        config.threshold = 1001;
        let detail = MlModel::load(config)
            .unavailable_detail()
            .expect("refused")
            .to_string();
        assert!(detail.contains("per-mille"), "got: {detail}");
    }

    #[test]
    fn an_incompatible_kind_and_architecture_is_refused() {
        let mut config = classifier_config(PathBuf::from("/nonexistent/model"));
        config.architecture = Architecture::BertMeanPooling;
        assert!(MlModel::load(config).unavailable_detail().is_some());
    }

    #[test]
    fn a_directory_whose_weights_are_corrupt_is_unavailable_with_a_cause() {
        // T011's stated acceptance. The digest pass reads the file before Candle maps it, so a truncated
        // or garbage safetensors file fails with a named cause rather than inside the model constructor.
        let dir = std::env::temp_dir().join(format!("please-ml-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        std::fs::write(dir.join("model.safetensors"), b"not a safetensors file").expect("write");
        std::fs::write(dir.join("config.json"), b"{}").expect("write");

        let result = MlModel::load(classifier_config(dir.clone()));
        let detail = result.unavailable_detail().expect("refused").to_string();
        assert!(!detail.is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }
}
