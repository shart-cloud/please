//! Row identity, labels, source and content hashes — the committed half of a corpus slice.
//!
//! This is the mechanism behind Principle IV's *"reproducible from a committed manifest"*. Prompt text
//! stays in [`crate::cache`]; `manifests/<slice>.jsonl` goes in git, and it is enough to answer the
//! question a reader of a published number is entitled to ask: **which rows, exactly?**
//!
//! # Row identity is the content hash
//!
//! The upstream dataset has no id column — `DESCRIBE` returns `prompt`, `response`, `model_name`,
//! `prompt_type`, `category`, `is_dangerous`, `source`, `language`, `prompt_harmful`,
//! `prompt_adversarial`, `response_harmful`, `response_refusal`, `attack_technique`, and nothing
//! resembling a key. The two candidates were parquet row order and the content hash.
//!
//! Row order loses. It is not promised stable across a dataset revision, so a manifest keyed on it
//! would verify successfully against different text after an upstream shard append — the failure mode
//! where the check still passes is the one worth designing against.
//!
//! The content hash wins twice. It identifies the row, and it *verifies* it: `manifest --check`
//! recomputing SHA-256 over cached text is a real check that the run being reported is the run that was
//! measured. DuckDB computes it during fetch (`sha256('abc')` returns the standard digest — checked
//! against `sha2` here, in [`tests::duckdb_and_sha2_agree`]) and this module recomputes it locally.
//!
//! # Why sampling needs no seed
//!
//! Because identity is a hash, `ORDER BY sha256` is a deterministic shuffle that every machine
//! agrees on. Every slice in `corpus/slices.toml` samples that way — `row_number() OVER (PARTITION BY
//! source ORDER BY sha256) <= 400` for the stratified ones — so there is no RNG state to record, no
//! seed to lose, and re-running `fetch` a year later against the pinned revision returns the same rows.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::rows::Row;
use crate::Result;

/// Length of the id prefix taken from the content hash.
///
/// 16 hex digits — 64 bits. Short enough to read in a report, and [`Manifest::write`] proves
/// uniqueness within each slice rather than trusting the birthday bound, because the cost of being
/// wrong is two rows silently sharing a metric and the cost of checking is one `BTreeMap`.
const ID_PREFIX: usize = 16;

/// One row's committed identity. **No prompt text**, and that is the whole design.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestRow {
    /// First [`ID_PREFIX`] hex digits of `sha256`. What reports and results refer to.
    pub id: String,
    /// Full SHA-256 of the prompt's UTF-8 bytes, lowercase hex.
    pub sha256: String,
    pub source: String,
    pub language: String,
    /// The corpus labels, carried verbatim rather than reduced to one boolean. They are orthogonal —
    /// WildGuard-style — and a manifest that recorded only "positive" would lose the ability to
    /// re-derive a slice under the other definition, which is exactly the ambiguity that made the two
    /// earlier ad-hoc negative sets irreconcilable.
    pub adversarial: u8,
    pub harmful: u8,
    /// Empty for the 94.8% of positives the corpus does not label.
    pub technique: String,
    /// Byte length of the prompt. Cheap, and it makes `corpus-analysis.md` Finding 6's size
    /// distribution re-derivable from the manifest alone.
    pub bytes: u64,
}

/// A slice's manifest, in file order.
#[derive(Debug, Clone, Default)]
pub struct Manifest {
    pub rows: Vec<ManifestRow>,
}

/// SHA-256 of some text, lowercase hex — the same digest DuckDB's `sha256()` produces.
pub fn digest(text: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    hasher
        .finalize()
        .iter()
        .fold(String::with_capacity(64), |mut acc, byte| {
            use std::fmt::Write;
            let _ = write!(acc, "{byte:02x}");
            acc
        })
}

/// The id a row is known by: the hash prefix.
pub fn id_for(sha256: &str) -> String {
    sha256.chars().take(ID_PREFIX).collect()
}

/// Path to a slice's committed manifest.
pub fn path(slice_id: &str) -> PathBuf {
    crate::crate_path(&format!("manifests/{slice_id}.jsonl"))
}

impl Manifest {
    /// Write the manifest for a slice, refusing to write one that could not identify its rows.
    ///
    /// Two refusals, both of which would otherwise surface as a quietly wrong metric:
    ///
    /// * a duplicate full hash means the same text is in the slice twice, so its contribution is
    ///   double-counted. Every query in `corpus/slices.toml` deduplicates by hash for this reason, and
    ///   this is the check that the query actually did;
    /// * a duplicate id prefix means two distinct rows share the name reports use for them.
    pub fn write(&self, slice_id: &str) -> Result<PathBuf> {
        let mut by_sha: BTreeMap<&str, ()> = BTreeMap::new();
        let mut by_id: BTreeMap<&str, &str> = BTreeMap::new();
        for row in &self.rows {
            if by_sha.insert(row.sha256.as_str(), ()).is_some() {
                return Err(format!(
                    "slice `{slice_id}`: duplicate content hash {} — the same text appears twice and \
                     would be counted twice. The slice's SQL should deduplicate by sha256",
                    row.sha256
                )
                .into());
            }
            if let Some(other) = by_id.insert(row.id.as_str(), row.sha256.as_str()) {
                return Err(format!(
                    "slice `{slice_id}`: id prefix {} is shared by two distinct rows ({other} and \
                     {}). Widen ID_PREFIX in src/manifest.rs",
                    row.id, row.sha256
                )
                .into());
            }
        }

        let target = path(slice_id);
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let mut out = String::new();
        for row in &self.rows {
            out.push_str(&serde_json::to_string(row)?);
            out.push('\n');
        }
        std::fs::write(&target, out)
            .map_err(|e| format!("cannot write {}: {e}", target.display()))?;
        Ok(target)
    }

    /// Read a slice's committed manifest.
    pub fn read(slice_id: &str) -> Result<Self> {
        let target = path(slice_id);
        let text = std::fs::read_to_string(&target).map_err(|e| {
            format!(
                "cannot read {}: {e}. Run `please-eval fetch --slice {slice_id}` to produce it",
                target.display()
            )
        })?;
        let mut rows = Vec::new();
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            rows.push(
                serde_json::from_str(line)
                    .map_err(|e| format!("{}:{}: {e}", target.display(), index + 1))?,
            );
        }
        Ok(Manifest { rows })
    }

    /// Verify cached text against the committed manifest.
    ///
    /// Fails naming the first mismatch, and reports what kind of mismatch it is, because the three
    /// causes need three different responses: a row count difference means the query or the upstream
    /// revision moved, a hash mismatch means the cached text is not what was measured, and a missing
    /// id means the cache was assembled by something other than `fetch`.
    pub fn verify(&self, slice_id: &str, cached: &[Row]) -> Result<()> {
        if cached.len() != self.rows.len() {
            return Err(format!(
                "slice `{slice_id}`: cache holds {} rows, manifest records {}. The query, the pinned \
                 revision, or the cache is not what was measured — re-run fetch",
                cached.len(),
                self.rows.len()
            )
            .into());
        }
        let by_id: BTreeMap<&str, &ManifestRow> =
            self.rows.iter().map(|r| (r.id.as_str(), r)).collect();
        for row in cached {
            let expected = by_id.get(row.id.as_str()).ok_or_else(|| {
                format!(
                    "slice `{slice_id}`: cached row `{}` is not in the manifest",
                    row.id
                )
            })?;
            let actual = digest(&row.text);
            if actual != expected.sha256 {
                return Err(format!(
                    "slice `{slice_id}`: row `{}` hashes to {actual}, manifest says {}. The cached \
                     text is not the text that was measured",
                    row.id, expected.sha256
                )
                .into());
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interoperability this module's identity scheme rests on: DuckDB computes the hash during
    /// fetch, `sha2` recomputes it during verification, and if the two ever disagreed every manifest
    /// in the repository would fail to verify for a reason nobody would look for here.
    #[test]
    fn duckdb_and_sha2_agree_on_the_standard_digest() {
        assert_eq!(
            digest("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            digest(""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn a_duplicate_hash_is_refused() {
        let row = ManifestRow {
            id: id_for(&digest("x")),
            sha256: digest("x"),
            source: "s".into(),
            language: "en".into(),
            adversarial: 1,
            harmful: 0,
            technique: String::new(),
            bytes: 1,
        };
        let manifest = Manifest {
            rows: vec![row.clone(), row],
        };
        // Writes into the real manifests/ directory only on success; this fails before touching disk.
        let err = manifest
            .write("test_duplicate_hash")
            .expect_err("a duplicated row must be refused");
        assert!(err.to_string().contains("counted twice"));
    }

    #[test]
    fn a_hash_mismatch_names_the_row() {
        let manifest = Manifest {
            rows: vec![ManifestRow {
                id: id_for(&digest("original")),
                sha256: digest("original"),
                source: "s".into(),
                language: "en".into(),
                adversarial: 0,
                harmful: 0,
                technique: String::new(),
                bytes: 8,
            }],
        };
        let mut tampered = Row::new(id_for(&digest("original")), "s", "tampered");
        tampered.language = Some("en".into());
        let err = manifest
            .verify("test_mismatch", std::slice::from_ref(&tampered))
            .expect_err("tampered text must fail verification");
        assert!(err
            .to_string()
            .contains("is not the text that was measured"));
    }
}
