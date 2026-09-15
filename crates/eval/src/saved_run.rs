//! Storage shared by corpus and bench runs. Domain manifests decide the selection and schema;
//! this module publishes bytes, records their identity, and verifies completeness before reporting.
//!
//! Corpus slices are published atomically. Bench rows remain a create-new stream whose identity
//! is published in the manifest only after syncing. Both manifest writers reserve `.pending` with
//! create_new and sync the directory after renaming. Interrupted files are retained as evidence.
//! Digests detect damaged artifacts, not replacement by someone who controls the whole cache.

use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::marker::PhantomData;
use std::path::{Path, PathBuf};

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::Result;

/// Corpus v1 completion identity; keep its wire fields unchanged.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedSlice {
    pub rows: usize,
    pub sha256: String,
}

/// Bench v1 completion identity, also produced when publishing corpus rows.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SavedFile {
    pub rows: u64,
    pub bytes: u64,
    pub sha256: String,
}

impl TryFrom<SavedFile> for SavedSlice {
    type Error = std::num::TryFromIntError;

    fn try_from(file: SavedFile) -> std::result::Result<Self, Self::Error> {
        Ok(Self {
            rows: file.rows.try_into()?,
            sha256: file.sha256,
        })
    }
}

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

/// A valid declaration plus verified results establishes completeness. Missing or invalid
/// declarations remain unverified, even when legacy rows can still be displayed.
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

    pub(crate) fn issue(&mut self, slice: Option<String>, detail: impl Into<String>) {
        self.issues.push(RunIssue {
            slice,
            detail: detail.into(),
        });
        if self.status == RunStatus::Complete {
            self.status = RunStatus::Incomplete;
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

/// Typed access to one saved directory. `at` performs no I/O; `create` refuses existing directories.
/// Callers retain their domain-specific manifest and selection validation.
pub struct SavedRun<Row> {
    directory: PathBuf,
    row: PhantomData<Row>,
}

impl<Row> SavedRun<Row> {
    pub fn at(directory: &Path) -> Self {
        Self {
            directory: directory.into(),
            row: PhantomData,
        }
    }

    pub fn create(directory: &Path) -> io::Result<Self> {
        fs::create_dir(directory)?;
        Ok(Self::at(directory))
    }

    pub fn read_manifest<M: DeserializeOwned>(&self) -> Result<M> {
        Ok(serde_json::from_slice(&fs::read(
            self.directory.join("run.json"),
        )?)?)
    }

    pub fn write_manifest(&self, manifest: &impl Serialize) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(manifest)?;
        let pending = self.directory.join(".run.json.pending");
        let mut file = new_file(&pending)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        drop(file);
        publish(&self.directory, &pending, "run.json")
    }

    /// Start a create-new result stream, preserving the bench's interrupted-run artifacts.
    pub fn stream_rows(&self, name: &str) -> Result<RowWriter<Row>> {
        validate_name(name)?;
        RowWriter::new(&self.directory.join(name))
    }

    /// Verify bench v1's byte count, newline count, and digest using bounded memory.
    /// Row parsing and domain validation remain separate from file-identity verification.
    pub fn verify_file(&self, name: &str, saved: &SavedFile) -> Result<()> {
        validate_name(name)?;
        let mut file = File::open(self.directory.join(name))?;
        let mut digest = Sha256::new();
        let mut bytes = 0u64;
        let mut rows = 0u64;
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            digest.update(&buffer[..count]);
            bytes += count as u64;
            rows += buffer[..count]
                .iter()
                .filter(|byte| **byte == b'\n')
                .count() as u64;
        }
        if bytes != saved.bytes
            || rows != saved.rows
            || format!("{:x}", digest.finalize()) != saved.sha256
        {
            return Err("bench results do not match their completion identity".into());
        }
        Ok(())
    }
}

impl<Row: Serialize> SavedRun<Row> {
    pub fn publish_rows(&self, name: &str, rows: &[Row]) -> Result<SavedFile> {
        validate_name(name)?;
        let pending = self.directory.join(format!(".{name}.pending"));
        let mut writer = RowWriter::new(&pending)?;
        for row in rows {
            writer.push(row)?;
        }
        let saved = writer.finish()?;
        publish(&self.directory, &pending, name)?;
        Ok(saved)
    }
}

impl<Row: DeserializeOwned> SavedRun<Row> {
    /// Corpus v1 counts nonblank parsed rows rather than newlines. Retain that distinction
    /// when reading old artifacts, including files without a trailing newline.
    pub fn read_slice(&self, name: &str, saved: &SavedSlice) -> Result<Vec<Row>> {
        validate_name(name)?;
        let bytes = fs::read(self.directory.join(name))
            .map_err(|e| format!("cannot read saved slice: {e}"))?;
        if digest(&bytes) != saved.sha256 {
            return Err(
                "saved slice checksum mismatch (corrupt, truncated, or modified results)".into(),
            );
        }
        let rows = parse_slice(&bytes)?;
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

    pub fn read_legacy_slice(&self, name: &str) -> Result<Option<Vec<Row>>> {
        validate_name(name)?;
        match fs::read(self.directory.join(name)) {
            Ok(bytes) => Ok(Some(parse_slice(&bytes)?)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.into()),
        }
    }

    pub fn inspect_slices<'a>(
        &self,
        finished: bool,
        selection: impl ExactSizeIterator<Item = (&'a str, Option<&'a SavedSlice>)>,
    ) -> (RunIntegrity, BTreeMap<String, Vec<Row>>) {
        let mut integrity = RunIntegrity {
            status: RunStatus::Complete,
            expected_slices: Some(selection.len()),
            verified_slices: 0,
            issues: vec![],
        };
        if !finished {
            integrity.issue(None, "run did not finish");
        }
        let mut results = BTreeMap::new();
        for (id, saved) in selection {
            let loaded = match saved {
                Some(saved) => self.read_slice(&format!("{id}.jsonl"), saved),
                None => Err("slice has no completion record".into()),
            };
            match loaded {
                Ok(rows) => {
                    integrity.verified_slices += 1;
                    results.insert(id.into(), rows);
                }
                Err(error) => integrity.issue(Some(id.into()), error.to_string()),
            }
        }
        (integrity, results)
    }

    /// Bench v1 ignores empty lines, but rejects whitespace-only lines as invalid JSON.
    pub fn rows(&self, name: &str) -> Result<impl Iterator<Item = Result<Row>>> {
        validate_name(name)?;
        let name = name.to_owned();
        let file = File::open(self.directory.join(&name))?;
        Ok(BufReader::new(file)
            .split(b'\n')
            .enumerate()
            .filter_map(move |(i, line)| match line {
                Ok(line) if line.is_empty() => None,
                Ok(line) => Some(
                    serde_json::from_slice(&line)
                        .map_err(|e| format!("{name}:{}: {e}", i + 1).into()),
                ),
                Err(error) => Some(Err(error.into())),
            }))
    }
}

/// A streamed result identity is available only after the complete stream has been flushed and synced.
pub struct RowWriter<Row> {
    writer: BufWriter<File>,
    digest: Sha256,
    rows: u64,
    bytes: u64,
    row: PhantomData<Row>,
}

impl<Row> RowWriter<Row> {
    fn new(path: &Path) -> Result<Self> {
        Ok(Self {
            writer: BufWriter::new(new_file(path)?),
            digest: Sha256::new(),
            rows: 0,
            bytes: 0,
            row: PhantomData,
        })
    }

    pub fn finish(mut self) -> Result<SavedFile> {
        self.writer.flush()?;
        self.writer.get_ref().sync_all()?;
        Ok(SavedFile {
            rows: self.rows,
            bytes: self.bytes,
            sha256: format!("{:x}", self.digest.finalize()),
        })
    }
}

impl<Row: Serialize> RowWriter<Row> {
    pub fn push(&mut self, row: &Row) -> Result<()> {
        let mut bytes = serde_json::to_vec(row)?;
        bytes.push(b'\n');
        self.writer.write_all(&bytes)?;
        self.digest.update(&bytes);
        self.bytes += bytes.len() as u64;
        self.rows += 1;
        Ok(())
    }
}

fn parse_slice<Row: DeserializeOwned>(bytes: &[u8]) -> Result<Vec<Row>> {
    std::str::from_utf8(bytes)?
        .lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(i, line)| {
            serde_json::from_str(line)
                .map_err(|e| format!("invalid saved row at line {}: {e}", i + 1).into())
        })
        .collect()
}

pub(crate) fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub(crate) fn validate_name(name: &str) -> Result<()> {
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

fn new_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

fn publish(directory: &Path, pending: &Path, name: &str) -> Result<()> {
    fs::rename(pending, directory.join(name))?;
    #[cfg(unix)]
    File::open(directory)?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    #[test]
    fn both_publication_modes_keep_v1_bytes_and_completion_fields() {
        let temp = tempfile::tempdir().unwrap();
        let run = SavedRun::<Value>::create(&temp.path().join("run")).unwrap();
        let rows = [json!({"id":"one"}), json!({"id":"two"})];
        let expected = b"{\"id\":\"one\"}\n{\"id\":\"two\"}\n";
        let atomic = run.publish_rows("slice.jsonl", &rows).unwrap();
        let mut stream = run.stream_rows("results.jsonl").unwrap();
        for row in &rows {
            stream.push(row).unwrap();
        }
        let streamed = stream.finish().unwrap();
        for name in ["slice.jsonl", "results.jsonl"] {
            assert_eq!(fs::read(run.directory.join(name)).unwrap(), expected);
            run.verify_file(name, &streamed).unwrap();
        }
        assert_eq!(
            serde_json::to_value(&atomic).unwrap(),
            json!({
                "rows": 2, "bytes": expected.len(), "sha256": digest(expected),
            })
        );
        let slice = SavedSlice::try_from(atomic).unwrap();
        assert_eq!(
            serde_json::to_value(&slice).unwrap(),
            json!({
                "rows": 2, "sha256": digest(expected),
            })
        );
        assert_eq!(run.read_slice("slice.jsonl", &slice).unwrap(), rows);
        assert_eq!(
            run.rows("results.jsonl")
                .unwrap()
                .collect::<Result<Vec<_>>>()
                .unwrap(),
            rows
        );
        assert!(run.stream_rows("results.jsonl").is_err());
        assert!(SavedRun::<Value>::create(&run.directory).is_err());
    }

    #[test]
    fn old_corpus_and_bench_row_count_conventions_remain_distinct() {
        let temp = tempfile::tempdir().unwrap();
        let run = SavedRun::<Value>::at(temp.path());
        let bytes = b"\n \t\r\n{\"id\":\"one\"}\r\n{\"id\":\"two\"}";
        fs::write(temp.path().join("legacy.jsonl"), bytes).unwrap();
        let saved = SavedSlice {
            rows: 2,
            sha256: digest(bytes),
        };
        assert_eq!(run.read_slice("legacy.jsonl", &saved).unwrap().len(), 2);
        assert_eq!(
            run.read_legacy_slice("legacy.jsonl")
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        // Bench v1 identities count newlines, independently of its stricter JSON row parser.
        let saved = SavedFile {
            rows: 3,
            bytes: bytes.len() as u64,
            sha256: digest(bytes),
        };
        run.verify_file("legacy.jsonl", &saved).unwrap();
        assert!(run
            .rows("legacy.jsonl")
            .unwrap()
            .collect::<Result<Vec<_>>>()
            .is_err());
    }

    #[test]
    fn bench_identity_rejects_count_size_and_checksum_damage() {
        let temp = tempfile::tempdir().unwrap();
        let run = SavedRun::<Value>::at(temp.path());
        let saved = run
            .publish_rows("results.jsonl", &[json!({"id":"one"})])
            .unwrap();
        for field in ["rows", "bytes", "sha256"] {
            let mut damaged = saved.clone();
            match field {
                "rows" => damaged.rows += 1,
                "bytes" => damaged.bytes += 1,
                _ => damaged.sha256 = "0".repeat(64),
            }
            assert!(
                run.verify_file("results.jsonl", &damaged).is_err(),
                "{field}"
            );
        }
    }
}
