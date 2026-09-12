//! Freeze owner-labeled captures without invoking the detector or displaying payloads.
//! Digests establish byte identity, not the truth of owner attestations or semantic novelty.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::replay::{Capture, Label};
use crate::Result;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Collection {
    format_version: u32,
    collection_id: String,
    owner: String,
    reviewed_at: String,
    /// Sampling rule and intended task/permissions, recorded before inspecting detector outcomes.
    protocol: String,
    /// One caller-owned permissions snapshot per collection; None means structural-only replay.
    export_policy_path: Option<PathBuf>,
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Case {
    capture: Capture,
    /// One conversation, attack family, or near-duplicate cluster stays in one split.
    group: String,
    split: Split,
    /// Where and when the exact scanner-boundary bytes were obtained; no credentials.
    provenance: String,
    task_context: String,
    labeler: String,
    previously_exposed: bool,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Split {
    Development,
    Holdout,
}

impl Split {
    fn name(self) -> &'static str {
        match self {
            Self::Development => "development",
            Self::Holdout => "holdout",
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Freeze {
    format_version: u32,
    frozen_at_unix_seconds: u64,
    draft_sha256: String,
    executable_sha256: String,
    /// Relative output paths and exact digests. Covers labels, protocol, exclusions and payloads.
    files: BTreeMap<String, String>,
    counts: BTreeMap<String, usize>,
}

fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn nonempty(value: &str, name: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(format!("{name} must not be empty").into());
    }
    Ok(())
}

/// Accepted exclusion rows are existing replay captures or authored experiment cases.
/// Refuse unreadable/empty/malformed exclusions rather than treating them as an empty history.
fn exposed(bytes: &[u8]) -> Result<BTreeSet<String>> {
    let mut hashes = BTreeSet::new();
    for line in std::str::from_utf8(bytes)?
        .lines()
        .filter(|l| !l.trim().is_empty())
    {
        let row: serde_json::Value = serde_json::from_str(line)?;
        let hash = match (row.get("input_sha256"), row.get("text")) {
            (Some(hash), _) => {
                let hash = hash
                    .as_str()
                    .filter(|h| valid_digest(h))
                    .ok_or("exclusion row has an invalid input_sha256")?;
                if let Some(text) = row.get("text") {
                    let text = text.as_str().ok_or("exclusion text must be a string")?;
                    if digest(text.as_bytes()) != hash {
                        return Err("exclusion row text disagrees with its input_sha256".into());
                    }
                }
                hash.to_owned()
            }
            (None, Some(text)) => digest(
                text.as_str()
                    .ok_or("exclusion text must be a string")?
                    .as_bytes(),
            ),
            _ => return Err("exclusion row needs input_sha256 or text".into()),
        };
        hashes.insert(hash);
    }
    if hashes.is_empty() {
        return Err("exclusion manifest is empty".into());
    }
    Ok(hashes)
}

/// Validate everything before creating the output directory. Payloads remain opaque bytes.
pub fn freeze(draft: &Path, exclusions: &[PathBuf], out: &Path) -> Result<String> {
    let draft_bytes = std::fs::read(draft)?;
    let mut collection: Collection = serde_json::from_slice(&draft_bytes)?;
    if collection.format_version != 1 {
        return Err("unsupported collection format_version".into());
    }
    for (value, name) in [
        (&collection.collection_id, "collection_id"),
        (&collection.owner, "owner"),
        (&collection.reviewed_at, "reviewed_at"),
        (&collection.protocol, "protocol"),
    ] {
        nonempty(value, name)?;
    }
    if collection.cases.is_empty() || exclusions.is_empty() {
        return Err("freeze requires reviewed cases and known-exposure manifests".into());
    }

    let mut known = BTreeSet::new();
    let mut files = BTreeMap::new();
    for (index, path) in exclusions.iter().enumerate() {
        let bytes = std::fs::read(path)?;
        known.extend(exposed(&bytes)?);
        // Retain only digests, never duplicate the exposed payload text into the holdout bundle.
        files.insert(
            format!("exclusions/{index:04}.sha256"),
            digest(&bytes).into_bytes(),
        );
    }
    files.insert(
        "known-exposed.json".to_string(),
        serde_json::to_vec_pretty(&known)?,
    );

    let parent = draft.parent().unwrap_or_else(|| Path::new("."));
    if let Some(path) = &collection.export_policy_path {
        let bytes = std::fs::read(parent.join(path))?;
        please_core::ExportPolicy::from_toml(std::str::from_utf8(&bytes)?)?;
        files.insert("export-policy.toml".to_string(), bytes);
        collection.export_policy_path = Some(PathBuf::from("export-policy.toml"));
    }
    let mut ids = BTreeSet::new();
    let mut identities = BTreeSet::new();
    let mut groups = BTreeMap::new();
    let mut content_splits = BTreeMap::new();
    let mut counts = BTreeMap::new();
    let mut benign_sources = BTreeSet::new();
    let mut holdout_injections = 0;
    let mut development = Vec::new();
    let mut holdout = Vec::new();
    for (index, case) in collection.cases.iter_mut().enumerate() {
        let capture = &mut case.capture;
        for (value, name) in [
            (&capture.id, "capture id"),
            (&capture.control_role, "control_role"),
            (&capture.label_reason, "label_reason"),
            (&case.group, "group"),
            (&case.provenance, "provenance"),
            (&case.task_context, "task_context"),
            (&case.labeler, "labeler"),
        ] {
            nonempty(value, name)?;
        }
        crate::replay::source(&capture.source)?;
        if !ids.insert(capture.id.clone()) {
            return Err("duplicate capture id".into());
        }
        let bytes = std::fs::read(parent.join(&capture.input_path))?;
        if digest(&bytes) != capture.input_sha256 {
            return Err("capture SHA-256 mismatch; labels must refer to the reviewed bytes".into());
        }
        if !identities.insert((
            capture.input_sha256.clone(),
            capture.source.clone(),
            capture.control_role.clone(),
        )) {
            return Err("duplicate input/source/role would inflate the sample counts".into());
        }
        for previous in [
            groups.insert(case.group.clone(), case.split),
            content_splits.insert(capture.input_sha256.clone(), case.split),
        ]
        .into_iter()
        .flatten()
        {
            if previous != case.split {
                return Err(
                    "related group or identical bytes cross development/holdout splits".into(),
                );
            }
        }
        if case.split == Split::Holdout {
            if case.previously_exposed || known.contains(&capture.input_sha256) {
                return Err("holdout contains a declared or known exposed capture".into());
            }
            match capture.label {
                Label::Benign => {
                    benign_sources.insert(capture.source.clone());
                }
                Label::Injection => holdout_injections += 1,
                Label::Uncertain => {}
            }
        }
        let label = match capture.label {
            Label::Benign => "benign",
            Label::Injection => "injection",
            Label::Uncertain => "uncertain",
        };
        *counts
            .entry(format!("{}/{}/{label}", case.split.name(), capture.source))
            .or_insert(0) += 1;
        let relative = format!("{}/inputs/{index:04}.bin", case.split.name());
        // Numeric filenames keep owner-controlled ids out of filesystem operations.
        capture.input_path = PathBuf::from(format!("inputs/{index:04}.bin"));
        let manifest = if case.split == Split::Holdout {
            &mut holdout
        } else {
            &mut development
        };
        serde_json::to_writer(&mut *manifest, capture)?;
        manifest.push(b'\n');
        files.insert(relative, bytes);
    }
    if benign_sources.len() != 3 || holdout_injections == 0 {
        return Err("holdout needs benign controls in all three sources and at least one injection; uncertain labels do not satisfy coverage".into());
    }
    files.insert("development/captures.jsonl".to_string(), development);
    files.insert("holdout/captures.jsonl".to_string(), holdout);
    // Collection paths are relative to collection.json; replay paths stay relative to each split.
    for case in &mut collection.cases {
        case.capture.input_path = Path::new(case.split.name()).join(&case.capture.input_path);
    }
    files.insert(
        "collection.json".to_string(),
        serde_json::to_vec_pretty(&collection)?,
    );
    let freeze = Freeze {
        format_version: 1,
        frozen_at_unix_seconds: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs(),
        draft_sha256: digest(&draft_bytes),
        executable_sha256: digest(&std::fs::read(std::env::current_exe()?)?),
        files: files
            .iter()
            .map(|(name, bytes)| (name.clone(), digest(bytes)))
            .collect(),
        counts,
    };
    let freeze_bytes = serde_json::to_vec_pretty(&freeze)?;
    // create_dir, not create_dir_all: never reuse an existing bundle. freeze.json is written last,
    // so an interrupted write is detectably incomplete. Parent directory must already exist.
    let mut directory = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        directory.mode(0o700);
    }
    directory.create(out)?;
    for (name, bytes) in files {
        let path = out.join(name);
        std::fs::create_dir_all(path.parent().ok_or("missing output parent")?)?;
        std::fs::write(path, bytes)?;
    }
    std::fs::write(out.join("freeze.json"), &freeze_bytes)?;
    Ok(digest(&freeze_bytes))
}

/// Require an external digest: replacing files and their colocated hashes must not pass unnoticed.
pub fn check(dir: &Path, expected: &str) -> Result<()> {
    let bytes = std::fs::read(dir.join("freeze.json"))?;
    if !valid_digest(expected) || digest(&bytes) != expected {
        return Err("freeze SHA-256 differs from the separately retained digest".into());
    }
    let freeze: Freeze = serde_json::from_slice(&bytes)?;
    if freeze.format_version != 1 || freeze.files.is_empty() {
        return Err("unsupported or empty freeze".into());
    }
    for (name, expected) in &freeze.files {
        let path = Path::new(name);
        if path.as_os_str().is_empty()
            || path
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("freeze contains a non-relative output path".into());
        }
        if digest(&std::fs::read(dir.join(path))?) != *expected {
            return Err(format!("frozen file changed: {name}").into());
        }
    }
    Ok(())
}
