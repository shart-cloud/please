//! Saved evaluation runs: fixed selection, atomic publication, and verified reporting.
//!
//! A result file alone proves neither that all selected slices ran nor that the file is complete.
//! The run records its selection before scanning, publishes each complete slice with a count and
//! digest, and records completion last. Readers verify the entire run before filtering presentation.
//! These digests detect damaged artifacts; they do not authenticate a cache against its owner.

use std::collections::{BTreeMap, BTreeSet};
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};

use please_core::Engine;
use please_scan::ScanSession;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::metrics::{Gate, Report, SliceMetrics};
use crate::product::Runtime;
use crate::rows::{Row, RowResult};
use crate::slice::SliceSet;
use crate::{scan, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    Complete,
    Incomplete,
    Unverified,
}

#[derive(Debug, Clone, Serialize)]
pub struct RunIssue {
    pub slice: Option<String>,
    pub detail: String,
}

/// Completeness is produced by inspecting saved records, not by counting passing metrics.
#[derive(Debug, Clone, Serialize)]
pub struct RunIntegrity {
    status: RunStatus,
    expected_slices: Option<usize>,
    verified_slices: usize,
    issues: Vec<RunIssue>,
}

impl RunIntegrity {
    pub fn is_complete(&self) -> bool {
        self.status == RunStatus::Complete
    }

    pub fn status(&self) -> RunStatus {
        self.status
    }

    pub fn issues(&self) -> &[RunIssue] {
        &self.issues
    }

    pub(crate) fn unverified(detail: impl Into<String>) -> Self {
        Self {
            status: RunStatus::Unverified,
            expected_slices: None,
            verified_slices: 0,
            issues: vec![RunIssue {
                slice: None,
                detail: detail.into(),
            }],
        }
    }

    #[cfg(test)]
    pub(crate) fn verified_for_test() -> Self {
        Self {
            status: RunStatus::Complete,
            expected_slices: Some(1),
            verified_slices: 1,
            issues: vec![],
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SavedSlice {
    rows: usize,
    sha256: String,
}

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
    directory: PathBuf,
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
        if let Err(error) = fs::create_dir(&directory) {
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
        let run = Self {
            directory,
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
        let mut bytes = Vec::new();
        for result in &results {
            serde_json::to_writer(&mut bytes, result)?;
            bytes.push(b'\n');
        }
        atomic_write(&self.directory, &format!("{id}.jsonl"), &bytes)?;
        self.completion.results.insert(
            id.to_string(),
            Some(SavedSlice {
                rows: rows.len(),
                sha256: digest(&bytes),
            }),
        );
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
        atomic_write(
            &self.directory,
            "run.json",
            &serde_json::to_vec_pretty(&metadata)?,
        )
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
    let mut metadata = Value::Null;
    let parsed = (|| -> Result<Completion> {
        metadata = serde_json::from_slice(&fs::read(directory.join("run.json"))?)?;
        let record = metadata
            .as_object_mut()
            .and_then(|m| m.remove("completion"))
            .ok_or("completion record is absent; older runs cannot prove completeness")?;
        let completion: Completion = serde_json::from_value(record)?;
        completion.validate(&metadata)?;
        Ok(completion)
    })();
    let (corpus, mut integrity, results) = match parsed {
        Ok(completion) => {
            let mut integrity = RunIntegrity {
                status: RunStatus::Complete,
                expected_slices: Some(completion.corpus.slices.len()),
                verified_slices: 0,
                issues: Vec::new(),
            };
            if !completion.finished {
                integrity.issues.push(RunIssue {
                    slice: None,
                    detail: "run did not finish".into(),
                });
            }
            let mut results = BTreeMap::new();
            for slice in &completion.corpus.slices {
                let loaded = match &completion.results[&slice.id] {
                    Some(saved) => {
                        read_verified(&directory.join(format!("{}.jsonl", slice.id)), saved)
                    }
                    None => Err("slice has no completion record".into()),
                };
                match loaded {
                    Ok(rows) => {
                        integrity.verified_slices += 1;
                        results.insert(slice.id.clone(), rows);
                    }
                    Err(error) => integrity.issues.push(RunIssue {
                        slice: Some(slice.id.clone()),
                        detail: error.to_string(),
                    }),
                }
            }
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
                let path = directory.join(format!("{}.jsonl", slice.id));
                match fs::read(&path) {
                    Ok(bytes) => match parse_rows(&bytes) {
                        Ok(rows) => {
                            results.insert(slice.id.clone(), rows);
                        }
                        Err(error) => integrity.issues.push(RunIssue {
                            slice: Some(slice.id.clone()),
                            detail: error.to_string(),
                        }),
                    },
                    Err(error) if error.kind() == ErrorKind::NotFound => {}
                    Err(error) => integrity.issues.push(RunIssue {
                        slice: Some(slice.id.clone()),
                        detail: error.to_string(),
                    }),
                }
            }
            (corpus, integrity, results)
        }
    };
    if !integrity.issues.is_empty() && integrity.status == RunStatus::Complete {
        integrity.status = RunStatus::Incomplete;
    }
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

fn read_verified(path: &Path, saved: &SavedSlice) -> Result<Vec<RowResult>> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read saved slice: {e}"))?;
    if digest(&bytes) != saved.sha256 {
        return Err(
            "saved slice checksum mismatch (corrupt, truncated, or modified results)".into(),
        );
    }
    let rows = parse_rows(&bytes)?;
    if rows.len() != saved.rows {
        return Err(format!(
            "saved slice has {} rows; expected {}",
            rows.len(),
            saved.rows
        )
        .into());
    }
    Ok(rows)
}

fn parse_rows(bytes: &[u8]) -> Result<Vec<RowResult>> {
    std::str::from_utf8(bytes)?
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            serde_json::from_str(line)
                .map_err(|e| format!("invalid saved row at line {}: {e}", index + 1).into())
        })
        .collect()
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
    {
        return Err(
            "run and slice names must be single names containing letters, digits, '-', '_', or '.'"
                .into(),
        );
    }
    Ok(())
}

fn atomic_write(directory: &Path, name: &str, bytes: &[u8]) -> Result<()> {
    let temporary = directory.join(format!(".{name}.pending"));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    fs::rename(&temporary, directory.join(name))?;
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(())
}
