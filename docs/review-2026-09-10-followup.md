# Release review follow-up — 2026-09-10

This records the first corrective pass. The subsequent [source-policy milestone](source-policies.md)
adds caller context, a policy snapshot to verdict JSON, and paired acceptance cases; its request
version supersedes the one recorded below.

This patch addresses verdict composition and truncation defects from the review of `1194d1b`,
plus the default-build ML test configuration and misleading quickstart commands.

## Changes

- `rejudge`, `with_ml`, and `add_gap` share a private rebuild state that retains coverage gaps,
  findings, truncation flags, target/ruleset attribution, and prior successful ML/judge reports.
  Demoting every finding from an incomplete scan now leaves `Inconclusive`. A later tier failure
  retains earlier reports and adds a gap.
- Direct and decoded observations carry `excerpt_truncated` into finalization. An active finding
  whose excerpt was shortened before finalization now records `ExcerptLength`. Quote suppression
  policy, including its treatment of suppressed excerpts, is unchanged.
- Judge requests check the complete sanitized, entity-escaped document against the 32 KiB limit.
  Inputs whose control characters, invalid UTF-8, or markup expand past that limit are refused.
  Literal markup in documents and excerpts is escaped; the prompt version is `2026-09-10.1`.
  This fixes literal delimiter framing, without establishing resistance to model manipulation.
- Real-weight tests require the `candle` feature, so cached weights no longer make default workspace
  tests attempt unavailable inference. The ML quickstart identifies its CLI examples as planned.

## Compatibility

`Observation` has a new public `excerpt_truncated: bool` field. Callers constructing observations
must set it to `false` for complete excerpts, or propagate the truncation result when shortening
an excerpt. The serialized verdict shape is unchanged; additional coverage gaps are intentional.
The judge prompt and data escaping changed and require fresh live evaluation before making
claims based on historical judgment measurements.

## Validation

Nine new regression tests reproduced the defects before the fixes and/or cover adjacent lifecycle
and size-boundary cases. They all pass after the fixes.

- `cargo test --workspace --offline --locked --no-fail-fast --quiet`: only the two existing fixture
  checks fail (43/51 positives detected, one false positive among 20 benign fixtures). The remaining
  tests pass. The run needed local mock HTTP servers outside the socket-restricted sandbox.
- `cargo test -p please-cli --no-default-features --offline --locked --quiet`: passed.
- `cargo build -p please-core --target wasm32-unknown-unknown --offline --locked --quiet`: passed.
- `cargo check -p please-ml --features candle --offline --locked --quiet`: passed.

No external model calls, model downloads, real-weight inference, production changes, or deployed
Worker tests were performed. Existing ignored live and performance tests remain ignored.

## Still open

Caller-owned surface profiles and representative benign/hostile pairs; review of suppressed-only
candidates; explicit CI matrix and enforced model-cache prerequisites; separate deterministic
fixture regression and release-quality gates retaining known-miss evidence; actual-policy evaluation;
CLI ML integration; Worker bindings, runtime tests, and resource measurements. These fixes do not
establish release readiness.
