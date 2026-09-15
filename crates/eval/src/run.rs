//! Saved evaluation runs: fixed selection, atomic publication, and verified reporting.
//!
//! A result file alone proves neither that all selected slices ran nor that the file is complete.
//! The run records its selection before scanning, publishes each complete slice with a count and
//! digest, and records completion last. Readers verify the entire run before filtering presentation.
//! These digests detect damaged artifacts; they do not authenticate a cache against its owner.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use crate::saved_run::{digest, validate_name, SavedRun, SavedSlice};
pub use crate::saved_run::{RunIntegrity, RunIssue, RunStatus};
use please_core::Engine;
use please_scan::ScanSession;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::metrics::{Gate, Report, SliceMetrics};
use crate::product::Runtime;
use crate::rows::{Row, RowResult};
use crate::slice::SliceSet;
use crate::{scan, Result};

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Completion {
    version: u32,
    metadata_sha256: String,
    selection_sha256: String,
    /// Resolved definitions preserve baseline, exclusions, and labels across corpus edits.
    corpus: SliceSet,
    results: BTreeMap<String, Option<SavedSlice>>,
    finished: bool,
}

impl Completion {
    fn validate(&self, metadata: &Value) -> Result<()> {
        if self.version != 1 || self.corpus.slices.is_empty() {
            return Err("unsupported or empty completion record".into());
        }
        if self.metadata_sha256 != digest(&serde_json::to_vec(metadata)?) {
            return Err("pipeline metadata does not match the completion record".into());
        }
        if self.selection_sha256 != digest(&serde_json::to_vec(&self.corpus)?) {
            return Err("saved slice definitions do not match the declared selection".into());
        }
        self.corpus.validate()?;
        let mut expected = BTreeSet::new();
        for slice in &self.corpus.slices {
            validate_name(&slice.id)?;
            expected.insert(slice.id.as_str());
        }
        if expected != self.results.keys().map(String::as_str).collect() {
            return Err("completion records do not match the expected slices".into());
        }
        if self
            .results
            .values()
            .flatten()
            .any(|r| r.sha256.len() != 64 || !r.sha256.bytes().all(|c| c.is_ascii_hexdigit()))
        {
            return Err("invalid slice checksum in completion record".into());
        }
        Ok(())
    }
}

/// A single writer owns a newly created run directory. Existing runs are never overwritten.
pub struct EvaluationRun<'a> {
    storage: SavedRun<RowResult>,
    metadata: Value,
    completion: Completion,
    session: ScanSession<'a>,
}

pub struct SliceSummary {
    pub rows: usize,
    pub hits: usize,
    pub floor: &'static str,
}

impl<'a> EvaluationRun<'a> {
    /// Persist the complete selection before input acquisition or scanning starts.
    pub fn create(
        results_root: &Path,
        label: &str,
        runtime: &'a Runtime,
        engine: &'a Engine,
        rules_description: &str,
        corpus: SliceSet,
    ) -> Result<Self> {
        validate_name(label)?;
        let metadata = runtime.metadata(engine, rules_description);
        let completion = Completion {
            version: 1,
            metadata_sha256: digest(&serde_json::to_vec(&metadata)?),
            selection_sha256: digest(&serde_json::to_vec(&corpus)?),
            results: corpus.slices.iter().map(|s| (s.id.clone(), None)).collect(),
            corpus,
            finished: false,
        };
        completion.validate(&metadata)?;
        fs::create_dir_all(results_root)?;
        let directory = results_root.join(label);
        let storage = match SavedRun::create(&directory) {
            Ok(storage) => storage,
            Err(error) => {
                if error.kind() == ErrorKind::AlreadyExists {
                    // Preserve the existing diagnostic for a mismatched pipeline, without permitting
                    // even an identical configuration to overwrite or extend a previous run.
                    if let Ok(bytes) = fs::read(directory.join("run.json")) {
                        if let Ok(mut previous) = serde_json::from_slice::<Value>(&bytes) {
                            if let Some(object) = previous.as_object_mut() {
                                object.remove("completion");
                            }
                            if previous != metadata {
                                return Err("run label already contains a different pipeline configuration; use a new --run label".into());
                            }
                        }
                    }
                    return Err("run label already exists; rerun with a new --run label".into());
                }
                return Err(error.into());
            }
        };
        let run = Self {
            storage,
            metadata,
            completion,
            session: runtime.session(engine),
        };
        run.persist()?;
        Ok(run)
    }

    /// Scan and publish all supplied rows as one slice; callers cannot save an arbitrary prefix
    /// while claiming that every input row was scanned.
    pub fn scan_slice(&mut self, id: &str, rows: &[Row]) -> Result<SliceSummary> {
        match self.completion.results.get(id) {
            Some(None) => {}
            Some(Some(_)) => {
                return Err(format!("slice {id} is already saved; use a new --run label").into())
            }
            None => return Err(format!("slice {id} is not in this run's fixed selection").into()),
        }
        let results = scan::rows_with_session(&self.session, rows);
        if results.len() != rows.len() {
            return Err(format!("slice {id} did not produce one result per input row").into());
        }
        let saved = self
            .storage
            .publish_rows(&format!("{id}.jsonl"), &results)?;
        self.completion
            .results
            .insert(id.to_string(), Some(saved.try_into()?));
        self.persist()?;
        Ok(SliceSummary {
            rows: rows.len(),
            hits: results.iter().filter(|r| r.detected).count(),
            floor: self.session.policy().threshold.as_str(),
        })
    }

    /// The last publication establishes that every selected slice finished.
    pub fn finish(mut self) -> Result<()> {
        if self.completion.results.values().any(Option::is_none) {
            return Err("run has unfinished slices; rerun with a new --run label".into());
        }
        self.completion.finished = true;
        self.persist()
    }

    fn persist(&self) -> Result<()> {
        let mut metadata = self.metadata.clone();
        metadata["completion"] = serde_json::to_value(&self.completion)?;
        self.storage.write_manifest(&metadata)
    }
}

/// Inspect every expected slice, then select the report view. `offline` cannot hide damage in a
/// saved public-corpus slice: inspection is local and never acquires data or creates directories.
pub fn report(results_root: &Path, label: &str, offline: bool) -> Result<Report> {
    validate_name(label)?;
    let directory = results_root.join(label);
    if !directory.is_dir() {
        return Err(format!(
            "no saved run {label}; run please-eval run with a new --run label first"
        )
        .into());
    }
    let storage = SavedRun::<RowResult>::at(&directory);
    let mut metadata = Value::Null;
    let parsed = (|| -> Result<Completion> {
        metadata = storage.read_manifest()?;
        let record = metadata
            .as_object_mut()
            .and_then(|m| m.remove("completion"))
            .ok_or("completion record is absent; older runs cannot prove completeness")?;
        let completion: Completion = serde_json::from_value(record)?;
        completion.validate(&metadata)?;
        Ok(completion)
    })();
    let (corpus, integrity, results) = match parsed {
        Ok(completion) => {
            let (integrity, results) = storage.inspect_slices(
                completion.finished,
                completion
                    .corpus
                    .slices
                    .iter()
                    .map(|slice| (slice.id.as_str(), completion.results[&slice.id].as_ref())),
            );
            (completion.corpus, integrity, results)
        }
        Err(error) => {
            // Legacy results remain inspectable, but present files cannot establish what was
            // originally selected. No compatibility option can turn this into a passing gate.
            let corpus = SliceSet::load()?;
            let mut integrity =
                RunIntegrity::unverified(format!("cannot verify run completeness: {error}"));
            let mut results = BTreeMap::new();
            for slice in &corpus.slices {
                match storage.read_legacy_slice(&format!("{}.jsonl", slice.id)) {
                    Ok(Some(rows)) => {
                        results.insert(slice.id.clone(), rows);
                    }
                    Ok(None) => {}
                    Err(error) => integrity.issue(Some(slice.id.clone()), error.to_string()),
                }
            }
            (corpus, integrity, results)
        }
    };
    let all_metrics: Vec<_> = corpus
        .slices
        .iter()
        .filter_map(|slice| {
            results
                .get(&slice.id)
                .map(|rows| SliceMetrics::compute(slice, rows))
        })
        .collect();
    // Gate the whole declared run; a presentation filter never weakens its result.
    let mut gate = Gate::evaluate(&corpus, &all_metrics);
    gate.run_integrity = integrity;
    if metadata.get("mode").and_then(Value::as_str) != Some("mechanism") {
        gate.unpinned = gate.slices.iter().map(|s| s.slice_id.clone()).collect();
        for slice in &mut gate.slices {
            slice.baseline = None;
            slice.regressed = false;
        }
    }
    let field = |key: &str| {
        metadata
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("legacy_unrecorded")
            .to_string()
    };
    let floor = metadata
        .get("policy")
        .and_then(|p| p.get("threshold"))
        .and_then(Value::as_str)
        .unwrap_or("legacy_unrecorded")
        .to_string();
    let metrics = all_metrics
        .into_iter()
        .filter(|m| !offline || !m.from_query)
        .collect();
    Ok(Report {
        run: label.into(),
        ruleset: format!("{}; mode={}", field("ruleset"), field("mode")),
        ruleset_digest: field("ruleset_digest"),
        floor,
        dataset: corpus.dataset.url(),
        metrics,
        gate,
    })
}
