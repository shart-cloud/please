//! Rendering a verdict, in the two forms the contract requires (FR-027).
//!
//! | Module | Reader | Stability |
//! |---|---|---|
//! | [`human`] | a person deciding whether the tool is right | prose; may be reworded |
//! | [`json`] | a hook, a pipeline, another program | **a published contract** — `contracts/verdict.schema.json` |
//!
//! The asymmetry is the reason for the split. Human output is tuned freely because nothing parses it; JSON
//! output is checked against the schema on every CI run, because changing it breaks callers who are not in
//! this repository (`contracts/cli.md`: "the shape of `--format json` is stable, and breaking it is a major
//! version change").
//!
//! Both write **one verdict at a time** into a writer the caller owns. Nothing here touches stdout
//! directly, so the invariant that only results reach it stays a property of one place in `main.rs`
//! rather than of every render path.
//!
//! # Why streaming, and why an enum
//!
//! Verdicts used to accumulate in a `Vec` and render into one `String` at the end, which made peak memory
//! a function of the corpus rather than of the largest target — a walk over a large tree exhausted memory
//! before printing anything. [`Emitter`] replaces that: `verdict` per target, `finish` once.
//!
//! An enum rather than a trait object because there are exactly two formats and both are known here.
//! Dispatch is a `match` the compiler can see through, and no allocation is involved.

use please_core::Verdict;

pub mod human;
pub mod json;

/// The chosen output form, rendering incrementally.
pub enum Emitter {
    Human(human::Emitter),
    Json(json::Emitter),
}

impl Emitter {
    /// A human-readable report.
    pub fn human(explain: bool) -> Self {
        Self::Human(human::Emitter::new(explain))
    }

    /// The machine-readable contract. `targets` decides object-versus-array and must be the count of
    /// resolved targets, not of verdicts produced so far.
    pub fn json(targets: usize) -> Self {
        Self::Json(json::Emitter::new(targets))
    }

    pub fn verdict<W: std::io::Write>(&mut self, w: &mut W, v: &Verdict) -> std::io::Result<()> {
        match self {
            Self::Human(e) => e.verdict(w, v),
            Self::Json(e) => e.verdict(w, v),
        }
    }

    /// Close the document — the human summary line, or the JSON array's bracket.
    pub fn finish<W: std::io::Write>(&mut self, w: &mut W) -> std::io::Result<()> {
        match self {
            Self::Human(e) => e.finish(w),
            Self::Json(e) => e.finish(w),
        }
    }
}
