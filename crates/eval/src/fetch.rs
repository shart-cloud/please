//! Corpus adapters: materialise a slice from the pinned upstream dataset into the cache.
//!
//! Access is by shelling out to the `hf` CLI — `hf datasets sql "<SQL>" --format json` — which is the
//! reproduction recipe `docs/research/corpus-analysis.md` already documents at the bottom of the file.
//! That is the reason for the choice rather than a consequence of it: the recipe in the documentation
//! and the code path in the harness are now the same thing, so neither can drift from the other, and a
//! reader who wants to check a number can run the query by hand.
//!
//! It also keeps a parquet reader and an HTTP client out of this crate. `hf datasets sql` runs DuckDB
//! against remote parquet over range reads, so a 400-row stratified sample does not download 411 MB.
//!
//! What this module refuses to do is report an empty or short slice as a result. Both failure modes
//! here — an unapproved dataset gate, a row that will not decode — have produced a wrong published
//! number before, and both are now named in the output.

use serde::Deserialize;
use std::process::Command;

use crate::manifest::{digest, id_for, Manifest, ManifestRow};
use crate::rows::Row;
use crate::slice::{Slice, SliceSet};
use crate::Result;

/// One row as the SQL projection returns it.
///
/// Deserialised into a struct rather than read from a `Value` so a change to a slice's projection is a
/// compile-or-parse error naming the missing column, not a column of empty strings in a report.
#[derive(Debug, Deserialize)]
struct QueryRow {
    sha256: String,
    source: Option<String>,
    language: Option<String>,
    adversarial: Option<i64>,
    harmful: Option<i64>,
    technique: Option<String>,
    bytes: Option<i64>,
    prompt: String,
}

/// What a fetch produced, including what it could not.
pub struct Fetched {
    pub slice_id: String,
    pub rows: usize,
    /// Rows the upstream returned that this harness could not use.
    ///
    /// Counted and reported, never dropped silently. `actionable-directive-results.md` records that a
    /// line-based reader *"silently dropped 5 LLMail rows whose prompts contain literal newlines, which
    /// is worth knowing before anyone reproduces this"* — five rows is nothing, and a reader finding out
    /// about them from a footnote in someone else's document is the actual problem. A dropped row is a
    /// coverage gap, which is the argument `Incompleteness` already makes inside the engine: absence of
    /// analysis must not be reported as absence of risk.
    pub decode_failures: usize,
    /// Digest disagreements between DuckDB and `sha2` over the same text. Expected to be zero; if it is
    /// ever not, the identity scheme in [`crate::manifest`] is broken and every manifest is suspect.
    pub digest_disagreements: usize,
}

/// Fetch one slice: run its SQL, write the cache file, write the manifest.
pub fn slice(set: &SliceSet, slice: &Slice) -> Result<Fetched> {
    let sql = set.sql(slice)?;
    let stdout = run_hf(&sql, slice)?;

    // `hf --format json` emits one JSON array. Parsed whole rather than line by line, which is the
    // fix for the dropped-newline rows above: a prompt containing `\n` is a perfectly ordinary JSON
    // string and only a line-oriented reader has a problem with it.
    let raw: Vec<serde_json::Value> = serde_json::from_str(&stdout).map_err(|e| {
        format!(
            "slice `{}`: cannot parse the output of `hf datasets sql` as JSON: {e}. The first 200 \
             bytes were: {}",
            slice.id,
            stdout.chars().take(200).collect::<String>()
        )
    })?;

    let mut rows: Vec<Row> = Vec::with_capacity(raw.len());
    let mut manifest = Manifest::default();
    let mut decode_failures = 0usize;
    let mut digest_disagreements = 0usize;

    for value in raw {
        let row: QueryRow = match serde_json::from_value(value) {
            Ok(row) => row,
            Err(_) => {
                decode_failures += 1;
                continue;
            }
        };

        // The digest is recomputed rather than trusted. DuckDB produced it upstream; if the two ever
        // disagree, the whole identity scheme is wrong and it is better to find out at fetch than to
        // discover a year of manifests cannot be verified.
        let local = digest(&row.prompt);
        if local != row.sha256 {
            digest_disagreements += 1;
        }

        let source = row.source.unwrap_or_else(|| "(unlabelled)".to_string());
        let language = row.language.unwrap_or_default();
        let technique = row.technique.unwrap_or_default();
        let id = id_for(&local);

        manifest.rows.push(ManifestRow {
            id: id.clone(),
            sha256: local,
            source: source.clone(),
            language: language.clone(),
            adversarial: row.adversarial.unwrap_or(0).clamp(0, 1) as u8,
            harmful: row.harmful.unwrap_or(0).clamp(0, 1) as u8,
            technique: technique.clone(),
            bytes: row.bytes.unwrap_or(row.prompt.len() as i64).max(0) as u64,
        });

        let mut scannable = Row::new(id, source, row.prompt);
        scannable.language = Some(language).filter(|s| !s.is_empty());
        scannable.technique = Some(technique).filter(|s| !s.is_empty());
        rows.push(scannable);
    }

    if rows.is_empty() {
        return Err(format!(
            "slice `{}` returned no rows. That is not a result — check the predicate in \
             corpus/slices.toml and that the pinned revision {} still exists",
            slice.id, set.dataset.revision
        )
        .into());
    }

    write_cache(&slice.id, &rows)?;
    manifest.write(&slice.id)?;

    Ok(Fetched {
        slice_id: slice.id.clone(),
        rows: rows.len(),
        decode_failures,
        digest_disagreements,
    })
}

/// Invoke `hf datasets sql`, distinguishing the failures an operator can act on.
fn run_hf(sql: &str, slice: &Slice) -> Result<String> {
    let output = Command::new("hf")
        .arg("datasets")
        .arg("sql")
        .arg(sql)
        .arg("--format")
        .arg("json")
        .output()
        .map_err(|e| {
            format!(
                "cannot run `hf`: {e}. The harness reaches the corpus through the Hugging Face CLI — \
                 install it, or set the slice aside with `--offline`"
            )
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // The gate on this dataset is `gated: "auto"`, so the common failure is a real one with a real
        // remedy, and a generic "command failed" would send the operator looking at the SQL instead.
        let gated = stderr.contains("gated")
            || stderr.contains("401")
            || stderr.contains("403")
            || stderr.contains("authentication");
        if gated {
            return Err(format!(
                "slice `{}`: the dataset gate refused access. Run `hf auth whoami` and check the \
                 account is approved for the repository named in corpus/slices.toml. The gate requires \
                 agreeing to respect the upstream licences of all 41 sources.\n\n{stderr}",
                slice.id
            )
            .into());
        }
        return Err(format!(
            "slice `{}`: `hf datasets sql` failed.\n\n{stderr}",
            slice.id
        )
        .into());
    }

    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Write cached rows as JSONL.
pub fn write_cache(slice_id: &str, rows: &[Row]) -> Result<()> {
    let path = crate::cache::slice_path(slice_id)?;
    let mut out = String::new();
    for row in rows {
        out.push_str(&serde_json::to_string(row)?);
        out.push('\n');
    }
    std::fs::write(&path, out).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    Ok(())
}

/// Read cached rows for a slice.
pub fn read_cache(slice_id: &str) -> Result<Vec<Row>> {
    let path = crate::cache::slice_path(slice_id)?;
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "cannot read {}: {e}. Run `please-eval fetch --slice {slice_id}` first",
            path.display()
        )
    })?;
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        rows.push(
            serde_json::from_str(line)
                .map_err(|e| format!("{}:{}: {e}", path.display(), index + 1))?,
        );
    }
    Ok(rows)
}
