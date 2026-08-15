//! `please-core` — the PLEASE prompt-injection detection engine.
//!
//! The verdict model, rule-set machinery, scoring, and the scan pipeline all landed with feature 001.
//! Feature 002 adds three modules that concentrate decisions currently spread across the crate:
//! [`prepare`] owns the transition from rule text to scanning capability, [`finalize`] owns the
//! transition from evidence to verdict, and [`matcher`] owns rule identity. All three are skeletons
//! until their phases land — see `specs/002-trustworthy-core/tasks.md`.
//!
//! Three properties of this crate are load-bearing and are proven mechanically rather than asserted
//! (constitution Principle V):
//!
//! * **No async runtime.** Callers include a pre-tool hook that must answer in milliseconds and a
//!   harness whose own constitution forbids a forced runtime.
//! * **No network, no filesystem, no clock.** Reading a target is the caller's job; this crate takes
//!   bytes. `std::time::Instant` in particular does not work on `wasm32-unknown-unknown`, so all
//!   bounds are counted (bytes, depth, matches) rather than timed.
//! * **Builds for `wasm32-unknown-unknown`.** CI proves it on every change.
//!
//! `#![forbid(unsafe_code)]` is set from the outset. A detection engine is the wrong place to earn
//! the right to `unsafe`.

#![forbid(unsafe_code)]

pub mod decode;
pub mod detect;
pub mod engine;
pub mod finalize;
pub mod matcher;
pub mod policy;
pub mod prefilter;
pub mod prepare;
pub mod ruleset;
pub mod sanitize;
pub mod score;
pub mod structure;
pub mod verdict;

pub use engine::{Engine, EngineBuilder};
pub use policy::ScanPolicy;
pub use ruleset::{Rule, Ruleset, RulesetError, RulesetLimits};
pub use verdict::{
    DetectionClass, EngineId, IncompleteCause, Incompleteness, Outcome, QuotingContext, Reason,
    RiskLevel, RulesetId, Span, TargetKind, TargetRef, Transform, TransformKind, Verdict,
    VerdictParts,
};

/// Engine name reported in every verdict's `engine` field (FR-005).
pub const ENGINE_NAME: &str = "please-core";

/// Engine version reported in every verdict's `engine` field (FR-005).
///
/// Read from the package version so a verdict can always be attributed to the build that produced
/// it, without a second place to update.
pub const ENGINE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn engine_identity_is_populated() {
        assert_eq!(ENGINE_NAME, "please-core");
        assert!(!ENGINE_VERSION.is_empty());
    }
}
