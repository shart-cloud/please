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
//! Both write into a `String` the caller prints in one go. Nothing here touches stdout, so the invariant
//! that only results reach it stays a property of one line in `main.rs` rather than of every render path.

pub mod human;
pub mod json;
