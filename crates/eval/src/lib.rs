//! `please-eval` — the evaluation harness for PLEASE.
//!
//! This crate produces the numbers behind every accuracy claim about PLEASE, and the constitution
//! (Principle IV) constrains how: **reproducible from a committed manifest, reported per source
//! stratum, never as a bare aggregate, with the false-positive rate as a first-class gate and the
//! known gaps stated alongside the metrics rather than left for a reader to infer.**
//!
//! Those are not stylistic preferences. `docs/research/corpus-analysis.md` measured a primary corpus
//! in which one source supplies 49.2% of the adversarial rows, so a headline aggregate over it is
//! substantially a score on that one source.
//!
//! # What lives here
//!
//! | module | owns |
//! |---|---|
//! | [`slice`] | the corpus slice model, parsed from `corpus/slices.toml` |
//! | [`cache`] | where fetched prompt text lives, and why it is not in git |
//! | [`fetch`] | corpus adapters — `hf datasets sql` invocation and cache materialisation |
//! | [`manifest`] | row identity, labels, source, content hashes. The reproducibility mechanism |
//! | [`rows`] | one scannable row, whatever it came from |
//! | [`cases`] | readers for the committed corpora: fixtures, generated rows, repository prose |
//! | [`scan`] | engine construction and the scan loop |
//! | [`metrics`] | stratified aggregation, report rendering, and the gate |
//! | [`generate`] | the carrier x payload x position generator, with span-level ground truth |
//!
//! # Two rules that apply to every module
//!
//! **Prompt text never enters git.** The primary corpus aggregates 41 sources that retain their own
//! licences. Fetched text lands in [`cache`] (gitignored); what is committed is a manifest — row
//! identity, labels, source, and a SHA-256 — which is sufficient to verify a run without
//! redistributing the data.
//!
//! **Every ratio is integer arithmetic.** Counts and per-mille, formatted from integers, never
//! floating point. `docs/research/document-map.md` §1.2 sets this rule for `Register` on portability
//! grounds; the same argument applies to a report. A number that differs in its last digit between an
//! x86 CI runner and an ARM laptop is a number nobody can reconcile, and integers cost nothing here.
//!
//! # What this crate does not do
//!
//! It does not tune detectors. `docs/002-accuracy-baseline.txt` exists so that a change moving
//! detection behaviour nobody asked it to move is a defect; building the instrument is not licence to
//! adjust the thing measured. What a measurement suggests gets written down.

/// Errors reach the operator as prose, because every one of them names something they have to fix —
/// an unapproved dataset gate, a manifest that no longer matches its cache, a carrier declaring an
/// anchor it does not contain. A typed error hierarchy would buy matching that nothing here does.
pub type Error = Box<dyn std::error::Error>;

/// Crate-wide result alias.
pub type Result<T> = std::result::Result<T, Error>;

pub mod cache;
pub mod cases;
pub mod fetch;
pub mod generate;
pub mod manifest;
pub mod metrics;
pub mod rows;
pub mod scan;
pub mod slice;

/// Absolute path to the repository root, resolved from this package's location.
///
/// The same `CARGO_MANIFEST_DIR` trick, and for the same reason, as `crates/core/tests/support.rs`:
/// a harness whose behaviour depends on the directory it was invoked from is a harness whose numbers
/// nobody else can reproduce.
pub fn repo_root() -> Result<std::path::PathBuf> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    root.canonicalize().map_err(|e| {
        format!(
            "cannot resolve the repository root from {}: {e}",
            root.display()
        )
        .into()
    })
}

/// Absolute path to a file inside this crate, e.g. `crate_path("corpus/slices.toml")`.
pub fn crate_path(relative: &str) -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}
