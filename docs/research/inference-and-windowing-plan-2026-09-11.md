# Inference identity and windowing implementation plan

Status: implementation of slices 1–4 completed, 2026-09-11. See
[inference-and-windowing-2026-09-11.md](inference-and-windowing-2026-09-11.md) for implementation
and validation evidence, plus [the local development sweep](window-boundary-measurement-2026-09-11.md).
This document preserves the accepted plan; held-out operating-point
selection remains conditional on data and explicit runtime criteria.

## Outcome and sequence

Make each local classifier result attributable to its artifacts and inference recipe, expose what
each window scored, and measure whether overlap improves boundary detection enough to justify its
cost. Implement in five independently reviewable slices, in order. Keep zero overlap as the default
until the experiment supports a change.

The starting point is `policy-and-pipeline-2026-09-11.md`. Enforcement, explicit reference analysis,
separate raw score and assessed impact, advisory review, retained analysis, and shared `ScanSession`
composition remain the governing contracts.

## What the code does today

- `crates/ml/src/model.rs` hashes only `model.safetensors`, before the backend reopens it. The backend
  independently reads `config.json` and `tokenizer.json`, disables padding/truncation, and runs CPU F32.
- `crates/ml/src/model/windows.rs` reserves special tokens, splits payload tokens with zero overlap,
  postprocesses each window, and preserves original-input offsets.
- `crates/ml/src/model/candle_backend.rs` quantizes each window's output and returns only its maximum.
- `crates/ml/src/scan.rs` emits a whole-document segment and at most one classifier observation.
- `MlReport` records model/revision/weights digest/threshold/impact/input digest. Product metadata
  repeats only part of this configuration, so tokenizer or window-size changes can evade run reuse checks.
- ML review binds the complete report and retained candidates. It permits at most 64 candidates;
  changing from one document candidate to many window candidates would change review semantics/cost.

## Slice 1 — Versioned inference identity, end to end

Deliver a shared value carried from model load into `MlReport`, review scope, and product `run.json`.
Keep pure value types in core; filesystem loading and backend details stay in ML. Suggested location:
`crates/core/src/inference.rs` and `crates/ml/src/model/identity.rs`, subject to existing export conventions.

Use three explicit layers:

1. Artifact identity: SHA-256 of weights, tokenizer JSON, and model config JSON, with the reported
   model name/revision retained as provenance. Paths are not content identity.
2. Inference recipe: schema/recipe version, architecture, model kind, malicious-label index,
   context size including special tokens, effective preprocessing overrides, special-token handling,
   payload window algorithm, overlap, max pooling, and per-mille rounding/calibration semantics.
   Record backend and resolved dependency/build identity, device and dtype. A package version alone
   cannot distinguish changed source in this currently dirty working tree; use a defined source/build
   fingerprint that also accounts for the relevant dependency lock and enabled features.
3. Decision/run configuration: admission threshold, impact, scan policy, ruleset and requested review
   configuration. These remain separate from raw inference identity: changing a threshold should
   change the run identity while leaving the raw inference identity unchanged.

Define a canonical, domain-separated encoding and hash it. Do not use Rust `Debug` formatting or
unspecified JSON map order as the stable identity contract. Carry readable fields alongside the digest.
Include effective/defaulted settings so omitted and explicit equivalent defaults compare equally.

Centralize artifact acquisition. Parse tokenizer/config from the same byte buffers that are hashed.
For weights, inspect the backend mapping API before choosing between a shared verified mapping and
an immutable load snapshot. Avoid a second full weight allocation by default. Document the unchanged-file
requirement of any mmap design; pre/post filesystem metadata checks alone do not prove immunity to
concurrent writes. Do not claim exact loaded-byte identity while hashing and loading unrelated opens.

Extend the schema additively and retain the existing weights `digest` meaning and compatibility
accessors. Older reports remain readable as identity-unrecorded; never manufacture a current identity
for them. Version evaluator metadata and reject reuse when inference or decision identity differs.
Keep legacy review eligibility unchanged in this attribution slice, but ensure new identities
participate in report equality and therefore invalidate stale review scopes.

When a product run requests a judge, also record its resolved non-secret endpoint/model, prompt/tool
contract digest and effective generation settings, separate from local inference identity. A remote
model name cannot guarantee immutable provider weights. Record that limit; do not imply full remote
reproducibility. Keep credentials and caller-context text out of ordinary metadata.

Acceptance: artifact, label, window, recipe or backend changes alter inference identity; path-only
changes do not. Threshold/impact changes alter run configuration without altering raw inference identity.
CLI and product evaluation expose the same identity. Mutation of identity invalidates pending review.
Missing/corrupt required artifacts still produce an unavailable tier. Old JSON remains readable.

## Slice 2 — Retain per-window results without changing decisions

Add a detailed classifier result containing the document maximum and an ordered list of window
results. Retain `classify()` as a compatibility wrapper over that result so there is one inference path.
Each result records a deterministic window index, payload token range, original-input byte span,
payload/model token counts and uncalibrated per-mille score. Define tie handling: earliest window index.

Derive byte spans from non-special-token offsets. Validate bounds and UTF-8 boundaries, including
normalization, repeated offsets, whitespace-only and empty input. Describe a span as the input region
represented by a window; it does not identify the exact malicious phrase. Token coverage and byte
envelope are different concepts because whitespace/normalization may not produce individual tokens.

Add a distinct `windows` representation to `MlReport`; preserve the existing whole-document summary
segment and single observation initially. Review continues to consider the complete document.
This exposes localization data without multiplying review candidates or changing clearance scope.
Window-scoped findings/review, if later needed, require a separate contract and experiment.

Bound result retention and inference work independently of display limits. Define a checked maximum
window/work budget in shared configuration and include it in run metadata. Exceeding it must record
incomplete coverage, never a successful partial scan. Preserve structural findings on failure.
Maintain atomic ML completion for this slice: no partial set of successful windows is presented as a
complete document result. Avoid duplicating input text or cloning full window lists per observation;
inspect the existing report-as-provenance representation before adding larger reports.

Acceptance: document maximum equals the maximum window score; single-window inference is unchanged;
zero-overlap multi-window scores and pre-review decisions match the existing algorithm. Raw scores
never select impact or contribute class breadth. Display shortening cannot alter retained windows,
decision or review binding. Window/work-budget failures are explicit. Schema/privacy tests cover output.

## Slice 3 — Configurable overlap through the shipping path

Add an optional `overlap_tokens` setting to shared classifier configuration, default zero. Define it
in payload-token units, after reserving special tokens. With payload capacity P and overlap O, require
0 <= O < P and advance by P - O. Reject invalid settings before inference. Emit no redundant trailing
window once the payload end is covered. Preserve special tokens on every window.

Use the production window helper and detailed result everywhere, including the evaluator. Add overlap
and algorithm version to inference identity. Recheck work limits before allocating/inferencing the
expanded window set; near-full overlap must not cause an unbounded cost multiplier.

Acceptance: zero reproduces slice 2 exactly; every payload token is covered, adjacent windows share
the requested token overlap, order/spans are deterministic, and max pooling is unchanged. Test empty,
exact-fit, one-token overflow, multi-window, UTF-8 and largest-valid overlap cases. Duplicate windows
cannot amplify assessed impact or class breadth. Configuration changes reject reuse of run labels.

## Slice 4 — Reproducible boundary-placement evaluation

Add a versioned boundary suite in `crates/eval`, using `ScanSession` with `shipping-ml`. Separate fixture
generation/coverage checks from optional real inference so ordinary CI needs neither weights nor a
provider. Reuse the existing capture/group-split conventions rather than creating an unrelated corpus.

Build paired attack and benign-control documents with configurable prefix/suffix padding. Place
payloads wholly within a window, immediately before/after a boundary, across it, at the first/last
window and across multiple boundaries. Include benign imperatives, quotations/code, tool-response
content, long benign dilution, multibyte text, and payloads longer than the overlap/window.

Compute placement with the actual loaded tokenizer and verify final offsets after tokenizing the
whole generated document. Padding can change tokenization at joins; nominal character positions are
insufficient. Freeze generated bytes/digests for paired comparisons across overlap settings. Keep
all placements of one source payload or family in the same development/holdout group.

Record input/suite identities, inference/run identities, requested and realized placement, all window
scores/spans, document score, product decision, coverage failures, windows/tokens processed, cold-load
time, warm latency distribution and peak memory. Keep runtime/hardware details separate from semantic
identity. Count failures/inconclusives explicitly rather than excluding them from accuracy denominators.

Report document-level detection/false positives by source, length and boundary position, with counts
and uncertainty. Treat related placements as a group when estimating uncertainty; they are not
independent samples. Compare both ML admission and the product block/review/allow outcome, since
structural findings can mask a classifier regression. Add a small offline CI matrix for deterministic
coverage and composition; real-weight measurements remain a separate reproducible command.

Acceptance: rerunning fixture generation reproduces bytes and manifests; invalid placements fail;
identity/config mismatches are rejected; fake-inference tests verify metric accounting and failures.
The existing mechanism gate remains explicitly separate from this product suite.

## Slice 5 — Measure, select and document the operating point

First measure the corrected zero-overlap shipping pipeline. On development data, compare zero with
candidate overlaps of approximately 1/8, 1/4 and 1/2 of payload capacity, recording the resolved integer
values. Hold model, threshold, impact, ruleset and profile fixed for this overlap experiment. Any later
threshold tuning is a separately identified experiment.

Before inspecting the holdout, freeze the candidate, grouped split, false-positive ceiling, acceptable
boundary-recall change, latency/memory/work ceilings and treatment of inconclusives. The historical
1% false-positive target is not a substitute for adequate sample size; report uncertainty and mark
insufficient evidence rather than claiming the target was met. Product latency/memory ceilings are
not established in the inspected code, so record explicit values before selecting a shipping default.

Select the smallest overlap that meets the frozen accuracy and cost criteria. If none qualifies, retain
zero and document the limitation. Validate the frozen candidate on the held-out groups without retuning.
Do local-model-only measurement first; paired judge measurements need separately identified prompts,
settings and response/cost capture and are a distinct run requiring authorized provider access.

Deliver a measurement report, machine-readable manifests/results, an explicit default decision, and
matching product baselines where supported. Do not apply historical mechanism baselines to these runs.
Update contracts, configuration examples and limits with the actual measured behavior.

## Review and validation checkpoints

Implement slices 1–4 as separate reviewable changes; split schema, loader and consumer wiring into
smaller commits if useful, with each commit compiling. Slice 5 is an experiment/report and any justified
default change. Do not combine unrelated embedding/outlier cleanup or test-suite reduction with this work.

For each code slice run focused semantic tests first. At integration checkpoints run workspace tests
with CLI Candle, CLI without default features, evaluator tests with both shipping tiers, formatting,
Clippy with warnings denied, schema/CLI contracts and existing dependency-isolation checks. Exercise
review identity mismatch, zero display limits and optional-tier failure paths after metadata changes.
Use the cached-tokenizer differential test when artifacts are available and a tiny deterministic
backend seam for ordinary CI. Real-model smoke/parity and accuracy results must be reported separately
from mocked tests. Run the historical offline mechanism gate as a regression check only.

This plan can begin with slice 1 without choosing a new overlap or obtaining fresh model results.
The concrete unresolved inputs for slice 5 are the available pinned model/corpus artifacts and the
product's acceptable runtime budgets. They do not block the attribution and reporting work.
