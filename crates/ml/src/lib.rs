//! `please-ml` — the optional local-inference tier (feature 006).
//!
//! A prompt-injection classifier and a segment embedder, loaded from safetensors on disk and run on CPU
//! through Candle. No network call, no API credential, no non-determinism from a remote model.
//!
//! # What this tier is for
//!
//! The structural tier is deterministic, auditable, and blind to vocabulary it has no rule for. The eval
//! baseline measures sixteen of twenty generated payloads as unreachable by it, with placement making no
//! difference to any of them. This tier addresses that gap, and only that gap. It is not a replacement for
//! the rules, not a replacement for the judgement tier, and not a content moderator.
//!
//! # What Phase 0 established, and what it cost
//!
//! Three findings from `specs/006-local-ml-tier/research.md` shape this crate more than the spec does:
//!
//! * **Candle on x86 is slower than the feature was scoped against.** T005 measured 183 ms per inference
//!   for ProtectAI and 444 ms for Prompt Guard 2, against the 50–150 ms taken from a third-party project
//!   on Apple Silicon. Selective inference (FR-652) is therefore load-bearing rather than an optimisation:
//!   a sixty-chunk document is eleven seconds on the cheaper model.
//! * **The embedding outlier score is a ranker, not a detector.** T006 measured 55.6% top-1 at finding a
//!   known payload; T008 measured 3.1% at deciding whether there is one, against a 25% criterion. See
//!   [`outlier`], which reports the score and gates nothing on it.
//! * **The corroboration requirement is gone.** It depended on the signal T008 killed. See [`observe`] for
//!   what was dropped, why, and what now stands in for it — which is less than what was there.
//!
//! # The dependency direction is the safety argument
//!
//! `please-core` never depends on this crate. That arrow is what keeps core's pinned dependency set, its
//! `#![forbid(unsafe_code)]`, and its `wasm32-unknown-unknown` build true regardless of what Candle drags
//! in — 112 crates and a memory-mapping `unsafe` block, measured in T001. Core may *describe* a
//! classification, through `MlReport`; only this crate may obtain one.
//!
//! This crate does not forbid unsafe, and `crates/ml/Cargo.toml` records why.
//!
//! # The backend is behind a feature
//!
//! `candle` is off by default. With it off the crate compiles in about a second, every type is present,
//! and the outlier arithmetic, the observation builder and config validation are all fully testable —
//! only inference itself is unavailable, and it reports that through [`MlLoadResult::Unavailable`] rather
//! than through a missing symbol.

pub mod config;
pub mod model;
pub mod observe;
pub mod outlier;

pub use config::{Architecture, MlConfig, ModelKind};
pub use model::{MlLoadResult, MlModel, Outcome};
pub use observe::{observe, Segment, ML_CLASS, ML_RULE_ID};

/// Core's vocabulary for describing a run, re-exported so a caller needs one import.
///
/// Producing an [`MlReport`](please_core::verdict::MlReport) is not producing a verdict: only
/// `please_core::finalize::with_ml` can apply one, and it is the thing that enforces the score never
/// falling.
pub mod verdict {
    pub use please_core::verdict::{MlMode, MlReport, MlSegmentResult, Span};
}
