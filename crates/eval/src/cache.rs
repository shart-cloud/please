//! Where fetched prompt text lives, and why it is not in git.
//!
//! Constitution Principle IV: *"Corpus text under third-party licence MUST NOT be vendored into this
//! repository. The repository carries manifests — identifiers, labels, source, and content hashes —
//! sufficient to verify a run without redistributing the data."* The primary corpus aggregates 41
//! sources that each retain their own licence, and the MIT licence on the aggregation covers the
//! aggregation code only.
//!
//! So the split is: text here, manifests in git. The default location is `~/.cache/please-eval`,
//! which the repository's `.gitignore` also covers via `/.cache/` should anyone point it inside the
//! tree.

use std::path::PathBuf;

use crate::Result;

/// The cache root: `$PLEASE_EVAL_CACHE`, else `$XDG_CACHE_HOME/please-eval`, else
/// `~/.cache/please-eval`.
///
/// The environment override is not a convenience. It is what lets a test run against a scratch
/// directory instead of the operator's real cache, and what lets a second checkout measure a
/// different revision without the two fighting over one directory.
pub fn root() -> Result<PathBuf> {
    if let Some(explicit) = std::env::var_os("PLEASE_EVAL_CACHE") {
        return Ok(PathBuf::from(explicit));
    }
    if let Some(xdg) = std::env::var_os("XDG_CACHE_HOME") {
        return Ok(PathBuf::from(xdg).join("please-eval"));
    }
    let home = std::env::var_os("HOME").ok_or(
        "neither PLEASE_EVAL_CACHE, XDG_CACHE_HOME nor HOME is set, so there is nowhere to cache \
         corpus text. Set PLEASE_EVAL_CACHE.",
    )?;
    Ok(PathBuf::from(home).join(".cache/please-eval"))
}

fn ensure(dir: PathBuf) -> Result<PathBuf> {
    std::fs::create_dir_all(&dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
    Ok(dir)
}

/// Fetched rows for one slice, as JSONL: the prompt text and its labels.
pub fn slice_path(slice_id: &str) -> Result<PathBuf> {
    Ok(ensure(root()?.join("slices"))?.join(format!("{slice_id}.jsonl")))
}

/// Scan results for one slice under one run label.
///
/// Results are derived data and stay out of git for a less principled reason than the text does: they
/// are large, they are reproducible from the manifest plus a commit, and a committed results file
/// would be a second place for a number to live and drift from the report beside it.
pub fn results_path(run: &str, slice_id: &str) -> Result<PathBuf> {
    Ok(ensure(root()?.join("results").join(run))?.join(format!("{slice_id}.jsonl")))
}

/// The directory holding one run's results.
pub fn results_dir(run: &str) -> Result<PathBuf> {
    ensure(root()?.join("results").join(run))
}
