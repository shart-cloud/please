//! What a caller must know about a model before it can be loaded.
//!
//! This crate deliberately does **not** read a manifest file. `please-eval` has one — `corpus/models.toml`,
//! with repo ids, revisions, per-file byte lengths and SHA-256 digests — because fetching is its job and a
//! fetcher needs a catalogue. Inference does not. Handing this crate a resolved [`MlConfig`] rather than a
//! path to a TOML file keeps `toml` out of the shipping graph and keeps the decision about *which* model to
//! run where it belongs: with the caller, in front of the operator, rather than buried in a default.

use std::path::PathBuf;

/// How the loaded model is meant to be used.
///
/// Named `ModelKind` rather than `Mode` because it is a property of the **weights**, not of the run: a
/// sequence classifier cannot be asked for an embedding and a sentence embedder has no malicious class.
/// The run's mode — which halves to invoke — is [`crate::verdict::MlMode`] on the report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelKind {
    /// A sequence classifier producing a probability over labels.
    Classifier,
    /// A sentence embedder producing a pooled vector.
    Embedder,
}

/// The weights' architecture, which decides how they are wired up.
///
/// An enum rather than a string read from `config.json`'s `architectures` field, because a mismatch here
/// is not a recoverable error — it is a model the caller believed was one thing and is another. Making it
/// a compile-time-known set means an unsupported architecture is refused at load with a name, rather than
/// silently producing a tensor of the wrong shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    /// DeBERTa-v2/v3 sequence classification. Both classifiers T002 and T003 measured are this, including
    /// Prompt Guard 2 — which T003 confirmed needs no ONNX path, closing that question.
    DebertaV2SequenceClassification,
    /// BERT with attention-mask-aware mean pooling and L2 normalisation — the Sentence Transformers
    /// recipe `all-MiniLM-L6-v2` was trained under. Pooling that averages padding into the vector is a
    /// common implementation error and would make similarity measure tokenizer padding.
    BertMeanPooling,
}

/// Everything needed to load and run one model.
#[derive(Debug, Clone)]
pub struct MlConfig {
    /// Directory holding `config.json`, `tokenizer.json`, and `model.safetensors`.
    pub model_path: PathBuf,
    /// Stable id for attribution — what lands in [`crate::verdict::MlReport::model`].
    pub model_id: String,
    /// Upstream revision the weights were fetched at. A repo id alone names a moving target.
    pub revision: String,
    pub kind: ModelKind,
    pub architecture: Architecture,
    /// Context window. Inputs longer than this are chunked (FR-612), never silently truncated —
    /// truncation would let a payload past the window score as whatever preceded it.
    pub max_tokens: usize,
    /// Index of the malicious class in the classifier's output. `None` for an embedder.
    ///
    /// Explicit rather than inferred from `id2label`, because T002 measured a real model whose config
    /// omits the mapping entirely. Inferring it would mean guessing, and a guess that lands on the wrong
    /// label inverts every verdict the tier produces — a failure that looks like a badly calibrated
    /// threshold rather than like a bug.
    pub malicious_label: Option<usize>,
    /// Threshold in per-mille, `0..=1000`. A segment at or above this is a finding.
    ///
    /// **This is the entire false-positive control.** `contracts/ml-tier.md` originally paired the
    /// classifier with a corroboration requirement; T008 measured the signal that requirement depended on
    /// at 3.1% TPR against a 25% criterion, and it was dropped rather than propped up. What remains is
    /// this number and SC-602's regression check.
    ///
    /// Two measurements bound it. T002 found ProtectAI scoring an ordinary imperative — *"Please translate
    /// the customer email into French"* — at 388, so no threshold below ~400 is available on that model at
    /// all. T003 found Prompt Guard 2 scoring the same class of text at 4. The models are not
    /// interchangeable at a shared default, which is why this is per-config rather than a constant.
    pub threshold: u16,
}

impl MlConfig {
    /// Reject a configuration that cannot describe a real run, before any weights are touched.
    ///
    /// Returns the reason as a string for the caller to put in an `Unavailable`. Separate from loading
    /// because these are questions about the *caller's request*, answerable without reading a gigabyte
    /// from disk — and a run rejected here costs nothing, where the same rejection after a 2.3 s load
    /// costs 2.3 s.
    pub fn validate(&self) -> Result<(), String> {
        if self.kind == ModelKind::Classifier && self.malicious_label.is_none() {
            return Err(format!(
                "model `{}` is a classifier but names no malicious label",
                self.model_id
            ));
        }
        if self.threshold > 1000 {
            return Err(format!(
                "threshold {} is out of range; per-mille means 0..=1000",
                self.threshold
            ));
        }
        if self.max_tokens == 0 {
            return Err(format!("model `{}` has a zero context window", self.model_id));
        }
        match (self.kind, self.architecture) {
            (ModelKind::Classifier, Architecture::DebertaV2SequenceClassification) => Ok(()),
            (ModelKind::Embedder, Architecture::BertMeanPooling) => Ok(()),
            _ => Err(format!(
                "model `{}` pairs an incompatible kind and architecture",
                self.model_id
            )),
        }
    }
}
