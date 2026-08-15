//! `please-eval` — evaluation harness for PLEASE.
//!
//! **Not implemented.** This crate is a placeholder so that its exclusion from the workspace is real
//! from the first commit rather than retrofitted after a stray dependency has already crept into the
//! shipping crates.
//!
//! When built out it will own:
//!
//! * corpus adapters, reaching the network to fetch and cache;
//! * the sampling manifest — row ids, labels, source, and content hashes. **Never prompt text:** the
//!   corpus aggregates 41 sources that retain their own licences, so only manifests belong in git
//!   (constitution Principle IV);
//! * per-source stratified metrics and the false-positive gate.
//!
//! The stratification is not a stylistic preference. One source supplies 49% of the adversarial rows
//! in the primary corpus, so a single aggregate score over it is substantially a score on that one
//! source — see `docs/research/corpus-analysis.md`.
//!
//! Until this crate exists, **no accuracy claim about PLEASE may be published.** Feature 001 verifies
//! accuracy against curated fixtures only, which bounds the risk but does not measure real-world
//! performance.
