//! `please-core` — the PLEASE prompt-injection detection engine.
//!
//! **Phase 1 scaffold.** The verdict model, rule-set machinery, scoring, and the scan pipeline arrive
//! in Phase 2 (tasks T011–T036). This file exists so the workspace builds and CI is green from the
//! first commit rather than red until the engine lands.
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
