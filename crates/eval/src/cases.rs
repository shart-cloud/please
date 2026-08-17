//! Readers for the corpora this repository owns and commits.
//!
//! Four of them, and between them they are everything the false-positive gate can run against in CI:
//! the labelled fixtures, the generated corpus, and the documentation tree. No network, no dataset
//! gate, no cache.
//!
//! The fixture reader duplicates the schema knowledge in `crates/core/tests/support.rs`, and that is
//! not ideal. Cargo does not let one package import another's integration-test module, and the
//! alternatives were worse: moving the loader into `please-core`'s public API would put a JSONL reader
//! in a crate whose central promise is that it does no filesystem access, and moving the fixtures into
//! this crate would take them away from the tests that gate on them. `tests/fixtures/README.md` is the
//! schema of record; both readers answer to it, and
//! [`tests::the_fixture_reader_agrees_with_the_core_suite`] pins the row counts so a drift shows up here.

use std::path::{Path, PathBuf};

use crate::rows::Row;
use crate::slice::LocalReader;
use crate::Result;

/// Read whichever committed corpus a local slice names.
pub fn read(reader: LocalReader) -> Result<Vec<Row>> {
    match reader {
        LocalReader::FixturesPositive => fixtures(Expected::Injection),
        LocalReader::FixturesBenign => fixtures(Expected::Benign),
        LocalReader::GeneratedPositive => generated(true),
        LocalReader::GeneratedMatchedNegative => generated(false),
        LocalReader::RepositoryProse => repository_prose(),
    }
}

#[derive(PartialEq, Eq, Copy, Clone)]
enum Expected {
    Benign,
    Injection,
}

/// Labelled cases from `tests/fixtures/*.jsonl`, filtered by label.
///
/// `source` is the fixture file's stem — `handcrafted-indirect`, `handcrafted-override`,
/// `handcrafted-repo-config` — rather than one flat "handcrafted". Per-source stratification is the
/// rule everywhere else in this harness and there is no reason for the fixtures to be the exception:
/// the file a case lives in is what it is probing.
fn fixtures(want: Expected) -> Result<Vec<Row>> {
    let dir = crate::repo_root()?.join("tests/fixtures");
    let mut files: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map_err(|e| format!("cannot read {}: {e}", dir.display()))?
        .filter_map(std::result::Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "jsonl"))
        .collect();
    // Sorted, because an unordered walk makes a failure report differ between runs — the determinism
    // position the whole project takes (SC-011), applied to the harness that measures it.
    files.sort();

    let mut rows = Vec::new();
    for file in &files {
        let stem = file
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("(unnamed)")
            .to_string();
        let text = std::fs::read_to_string(file)
            .map_err(|e| format!("cannot read {}: {e}", file.display()))?;
        for (index, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let value: serde_json::Value = serde_json::from_str(line)
                .map_err(|e| format!("{}:{}: {e}", file.display(), index + 1))?;
            let field = |name: &str| -> Result<String> {
                value
                    .get(name)
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .ok_or_else(|| {
                        format!(
                            "{}:{}: missing required field `{name}` (see tests/fixtures/README.md)",
                            file.display(),
                            index + 1
                        )
                        .into()
                    })
            };
            let expected = match field("expected")?.as_str() {
                "benign" => Expected::Benign,
                "injection" => Expected::Injection,
                other => {
                    return Err(format!(
                        "{}:{}: `expected` must be \"benign\" or \"injection\", got {other:?}",
                        file.display(),
                        index + 1
                    )
                    .into())
                }
            };
            if expected != want {
                continue;
            }
            let mut row = Row::new(field("id")?, stem.clone(), field("text")?);
            row.context = Some(field("context")?);
            row.difficulty = Some(field("difficulty")?);
            rows.push(row);
        }
    }
    Ok(rows)
}

/// Rows from `corpus/generated.jsonl`, split by whether they carry a payload.
///
/// The file is written by [`crate::generate`] in [`Row`]'s own shape, so this reader deserialises
/// rather than re-parses. A carrier row has no `injected_span` — that absence *is* the matched-negative
/// label, and it cannot drift from the text the way a separate boolean could.
fn generated(with_payload: bool) -> Result<Vec<Row>> {
    let path = crate::crate_path("corpus/generated.jsonl");
    let text = std::fs::read_to_string(&path).map_err(|e| {
        format!(
            "cannot read {}: {e}. Run `please-eval generate` to produce it",
            path.display()
        )
    })?;
    let mut rows = Vec::new();
    for (index, line) in text.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let row: Row = serde_json::from_str(line)
            .map_err(|e| format!("{}:{}: {e}", path.display(), index + 1))?;
        if row.injected_span.is_some() == with_payload {
            rows.push(row);
        }
    }
    Ok(rows)
}

/// Every `.md` under `docs/` and `specs/` — this repository's own security prose.
///
/// The hardest negative class there is, and the one no public source covers: a threat model, a rule
/// justification or a research memo contains payload strings as subject matter.
/// `docs/research/actionable-directive-results.md` §2.3 shows the shipped rule set firing on 12 of
/// these 38 documents, one of them the sentence in a design memo that enumerates the very verb list a
/// detector matches on.
///
/// `source` is the top-level directory, so `docs` and `specs` report separately. They are different
/// populations: `docs/` is prose about attacks, `specs/` is requirements that quote them.
fn repository_prose() -> Result<Vec<Row>> {
    let root = crate::repo_root()?;
    let mut rows = Vec::new();
    for top in ["docs", "specs"] {
        let mut paths = Vec::new();
        collect_markdown(&root.join(top), &mut paths)?;
        paths.sort();
        for path in paths {
            let relative = path
                .strip_prefix(&root)
                .unwrap_or(&path)
                .to_string_lossy()
                .into_owned();
            // Lossy, and deliberately: a `.md` file that is not valid UTF-8 is still a document an
            // agent could be handed, and skipping it would shrink the denominator silently.
            let text = String::from_utf8_lossy(
                &std::fs::read(&path)
                    .map_err(|e| format!("cannot read {}: {e}", path.display()))?,
            )
            .into_owned();
            if text.trim().is_empty() {
                continue;
            }
            rows.push(Row::new(relative, top, text));
        }
    }
    Ok(rows)
}

fn collect_markdown(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    for entry in
        std::fs::read_dir(dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?
    {
        let path = entry
            .map_err(|e| format!("cannot read an entry of {}: {e}", dir.display()))?
            .path();
        // No symlink following. `crates/cli` had to fix exactly this in a directory walk (commit
        // 4a8708b, "a walk holds one target at a time, and stops following symlinks"), and a corpus
        // reader that can be sent round a cycle by a symlink in the tree has the same defect.
        let meta = std::fs::symlink_metadata(&path)
            .map_err(|e| format!("cannot stat {}: {e}", path.display()))?;
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            collect_markdown(&path, out)?;
        } else if path.extension().is_some_and(|ext| ext == "md") {
            out.push(path);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The counts `docs/004-accuracy-baseline.txt` and `docs/002-accuracy-baseline.txt` are written
    /// against. If this reader and `crates/core/tests/support.rs` ever disagree about how many cases
    /// exist, every fixture number in this harness is being computed over a different denominator than
    /// the core suite's — so the duplication this module opens by admitting to gets a check rather than
    /// a promise.
    #[test]
    fn the_fixture_reader_agrees_with_the_core_suite() {
        let positives = fixtures(Expected::Injection).expect("fixtures must load");
        let benign = fixtures(Expected::Benign).expect("fixtures must load");
        assert!(
            positives.len() >= 41,
            "expected at least the 41 positives the 004 baseline pins, found {}",
            positives.len()
        );
        assert!(
            !benign.is_empty(),
            "no benign fixtures: the gate would pass vacuously"
        );
        for row in positives.iter().chain(benign.iter()) {
            assert!(!row.text.is_empty(), "{}: empty text", row.id);
            assert!(row.context.is_some(), "{}: no context", row.id);
        }
    }

    #[test]
    fn repository_prose_is_found_and_stratified() {
        let rows = repository_prose().expect("the documentation tree must be readable");
        assert!(
            rows.len() > 20,
            "found only {} markdown documents; the prose slice is the hardest negative class and a \
             short one is a weakened gate",
            rows.len()
        );
        assert!(rows.iter().any(|r| r.source == "docs"));
        assert!(rows.iter().any(|r| r.source == "specs"));
    }
}
