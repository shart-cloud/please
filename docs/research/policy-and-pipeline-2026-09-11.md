# Explicit profiles, ML assessment, and shared scan sessions — 2026-09-11

This implements the three follow-ups to retained analysis: separate caller policy inputs, separate
classifier output from assessed impact, and share shipping composition with evaluation.

## Profiles and trusted context

`ScanPolicy::default()` now selects `ScanProfile::Enforcement`. Quotes, code fences, and example
claims cannot suppress findings in this profile, even if `suppress_in_quotes` is set to true.
`ScanPolicy::reference_analysis()` explicitly enables reference analysis and quote suppression.
Reference analysis can still report unquoted instructions and structural concealment findings.

`InputProvenance` records host-established origin (`unspecified`, `caller_provided`, `user_input`, or
`tool_response`). It is independent of profile and review authority. For example, a caller may select
a tool response for reference analysis without pretending its origin changed. This is an explicit
host decision; document contents, filenames, model outputs, and dataset labels cannot select it.

The former `ScanSource` enum and CLI `--source` remain compatibility adapters. `for_source` maps
`SecurityReference` to caller-provided/reference analysis and untrusted user/tool sources to
enforcement. New integrations should set provenance and profile separately. A direct assignment to
the legacy source field does not grant a reference-analysis exception. Omitting source now uses
enforcement, changing the old default behavior deliberately.

```sh
plz scan --profile enforcement --provenance tool-response response.txt
plz scan --profile reference-analysis --provenance caller-provided lesson.md
```

`CallerContext` lives in core and describes the host's task, typed permission boundaries, and known
versus unavailable scopes. Set `ScanPolicy::caller_context` before scanning. The CLI accepts a
host-owned JSON file through `--review-context PATH` with `--judge`. `Judge::review` automatically
uses contextual routing when a bound context exists. Compatibility methods accepting a separate
context reject any mismatch before a request. Captured review scopes include the bound context;
responses cannot be applied after task or permission context changes.

Ordinary output records `scan_policy.caller_context_id`, not task or permission text. Context text
is sent to the requested judge as caller context. It must describe policy without secret values.
Input provenance must be established for contextual review; missing relevant permissions remain
indeterminate. Review authority remains separate: advisory by default, with release requiring the
explicit `--judge-allow-release` or `ReviewAuthority::MayRelease` opt-in.

## Classifier score versus impact

The classifier emits a quantized per-mille `raw_score`. Reports mark `calibration: "uncalibrated"`;
this is not a calibrated probability that a real policy violation occurred. The Rust `probability()`
accessor remains an alias for compatibility. The JSON schema accepts historical `probability` fields,
but current producers use `raw_score`.

The configured threshold controls admission only. Every admitted production classifier finding uses
`ScanPolicy::ml_impact`, a validated `MlImpact` in 0–100, also exposed as `--ml-impact`. Its default is
75, an explicit provisional policy choice. Changing threshold or raw score cannot change the severity
of a finding admitted under the same impact policy. Reports record `assessed_impact` separately.
The previous threshold-dependent 40–75 severity ramp is removed.

All observations entering through ML finalization are excluded from the structural class-breadth
bonus, including legacy/unbound ML reports. Their assessed severity may still raise the aggregate
score. `AgentDirected` remains the compatibility reporting category; it is not a measured behavioral
classification. `class_breadth: false` makes that distinction visible on ML reasons. This does not
change how actual structural detections in that class contribute.

## One shipping composition

The new `please-scan` crate supplies `ScanSession` and `ScanDecision`:

```rust
let session = please_scan::ScanSession::new(&engine, policy);
// Optional, feature-gated: session.with_model(&model).with_judge(&judge)
let verdict = session.scan(input, target);
let decision = session.decision(&verdict);
```

A session owns a policy snapshot and borrows the engine and requested tiers. Its fixed order is
structural analysis → local classifier → review. The input limit prevents optional-tier execution;
requested tier failures accumulate gaps without removing retained evidence. The default dependency
graph has no optional inference or judge stack. Core still has no filesystem, network, clock, or
subprocess access. No plugin framework or asynchronous runtime was introduced.

The CLI, ordinary evaluation rows, and saved-baseline replay use this session. Local classifier
configuration loading moved from the CLI into this shared crate. The CLI and evaluator share threshold
interpretation through `ScanDecision`; caller presentation and acquisition remain outside it.

`please-eval run` defaults to `--mode product`, using enforcement and the shipping High threshold.
`--mode mechanism` explicitly preserves the historical structural/reference-analysis operating point
and its Low detection floor. CI's historical false-positive gate selects this mode explicitly.
Product runs can configure profile, provenance, threshold, and optional shipping tiers:

```sh
cargo run --manifest-path crates/eval/Cargo.toml -- \
  run --offline --run product-enforcement
cargo run --manifest-path crates/eval/Cargo.toml --features shipping-ml,shipping-judge -- \
  run --offline --run product-reviewed --provenance tool-response \
  --ml-config /path/to/ml-config.json --ml-impact 75 --judge --review-context /path/to/context.json
```

`run.json` records mode, policy, enabled tiers, model metadata where available, and the actual scanned
ruleset identity. Reporting reads that identity rather than deriving it from whatever rules happen
to be installed later. Reusing a run label with another configuration is rejected. Historical runs
without metadata are labeled unrecorded rather than assigned a current ruleset identity.

Historical per-slice baselines do not apply to product mode. Its report marks those comparisons
unpinned, so the gate fails by default until a matching baseline is explicitly established. The
legacy model-feasibility experiments remain under eval's separate `ml` feature and are not the
shipping pipeline; the shipping model path is `shipping-ml`.

## Validation and limits

Regression coverage includes plain/quoted/fenced/tool inputs under enforcement, explicit reference
analysis, context changes invalidating pending clearances, context privacy in JSON output, threshold
and raw-score independence of impact, absent ML class-breadth bonuses, optional-tier failure
composition, zero display limits, CLI/session parity, product/session row parity, historical mode,
and rejection of mixed run configurations.

Completed checks: workspace tests with CLI Candle support, offline CLI tests, evaluator tests with
both shipping tiers enabled, workspace and evaluator Clippy with warnings denied, formatting,
and core/CLI/ML dependency isolation checks. CI now also runs the evaluator's optional-tier product
contract tests. The offline mechanism gate passed: benign fixtures 1/20, matched negatives 0/14,
and repository prose 15/72, all within their recorded regression baselines. This gate pass does not
mean all slices meet the 1% false-positive criterion.

No live external judge call or model-weight inference was used to validate these changes. The new
profile, severity policy, and prompt version (`2026-09-11.7`) need fresh accuracy and operating-cost
measurements before old research results can be attributed to them. Context binding establishes
which caller policy was supplied; it does not establish that a supplied policy is correct or that an
authorized reviewer will resist manipulation.

The inference identity, per-window reporting, configurable overlap and boundary evaluation follow-ups
are implemented in [the subsequent slice](inference-and-windowing-2026-09-11.md). Selecting a new
shipping overlap still requires held-out accuracy and runtime-budget evidence.
