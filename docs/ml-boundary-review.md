# ML instruction-boundary review

`please-judge` implements the opt-in `ml-boundary-review-v1` contract. It is available to library
callers and offline evaluation tools. The CLI's existing `--judge` routing remains the preserved
candidate routing. Reviews now default to advisory; demotions require explicit
`ReviewAuthority::MayRelease`. See [review authority and binding](research/review-boundaries-2026-09-11.md).
No live semantic accuracy measurement has been performed for this route.

## Calling the review

Prefer `please_scan::ScanSession` for shipping composition. Bind `ScanPolicy::caller_context`
before scanning. Low-level callers can still choose:

- `Judge::review_ml(verdict, input, bands, &context)` reviews only ML findings.
- `Judge::review_with_ml_context(verdict, input, bands, &context)` separately reviews structural
  findings and ML findings, supplying both with the same caller-owned context. The ML mapping is
  frozen before structural demotions, so reordered reasons cannot change its targets.
- `Judge::review` uses contextual routing when caller context is bound, and advisory authority by default.

Construct `please_core::CallerContext` (also re-exported as `please_judge::ml_review::ReviewContext`) in the host. It contains `task_context`, typed
`boundaries` (each with an explicit `scope` and `constraint`), and `context_completeness` with
`relevant`, `known`, and `unavailable` scope lists. Input provenance and the analysis profile come from the scan policy.
Do not fill these fields from document claims, upstream labels, or the review response. Supply
policy descriptions and resource identifiers, never secret values.

For example, a direct user-input hierarchy experiment can supply an `InstructionHierarchy`
boundary, mark that scope relevant and known, and describe how user requests are processed. This
is a host assertion about that experiment's scope; it does not establish export authorization.
For a use involving protected data or tool actions, include those relevant scopes and their
actual constraints. Mark missing object/destination authorization unavailable. Tool responses and
security references also need a task description before any ML clearance can be actionable.

The host generates boundary IDs `b0`, `b1`, etc., and candidate IDs `c0`, `c1`, etc. The request
contains the complete rendered document and candidate scopes, without classifier probabilities,
severity, rule IDs, model rationale, or dataset labels. It is bounded to 128 KiB after encoding,
with at most 64 candidates and 32 boundaries. Oversized input is refused, never shortened for review.

## Offline responses and capture

`MlReviewRequest::assemble(&verdict, input, &context)` freezes the request and private candidate
mapping. `user_content()` exposes the exact user-message string and `request_id()` its host binding.
The ID hashes the contract version, input-bound scan/provenance identity, and encoded request content;
it is not a hash of the entire HTTP request. Record the resolved model, endpoint, system prompt,
tool schema, generation settings, and exact HTTP-request hash separately for paired experiments.

Use `apply_response(verdict, tool_input_json, model, bands)` for controlled offline tool responses,
or `apply_envelope(verdict, raw_messages_response, model, bands)` to replay a captured response.
Both call the same strict parser and ML-only finalizer as `Judge::review_ml`.

`client::send_ml_review` returns the exact successful response body for private capture before
parsing. `client::send_captured` provides the equivalent baseline seam without changing its request
prompt or schema. Neither writes files. Store requests, raw responses, and model rationales only in
ignored private evaluation storage; retain transport errors as failures in the metrics denominator.
No live calls are required to run the offline tests.

The closed response has `contract_version`, `request_id`, and `results`. Each result contains:

- `candidate_id`, the complete requested `scope`, and `outcome`;
- `boundary_ids`, a nonempty bounded `rationale`, and an `evidence` array;
- `behavior` only for `supported_violation`, where it is required alongside a known boundary and
  nonempty evidence.

`no_supported_violation` must assess all supplied boundaries and requires sufficient host context.
Its evidence can be empty. `indeterminate` retains the finding and records review incompleteness.
Each evidence entry has `start`, `end`, and `quote`, checked against UTF-8 byte offsets in the decoded
`analysis_text` string, including its entity spellings and neutralized controls. These positions are
not original-input offsets. The implementation does not display model evidence as original-input
positions; a future evidence display must retain a rendering/source map.

Unknown fields, duplicate JSON fields or IDs, missing candidates, incompatible identities, invalid
ranges, contradictory result fields, truncated envelopes, multiple tool calls, and transport failures
reject the response as a whole. No partial malformed response can clear a subset of candidates.

## Finalization and compatibility

Engine scans retain a private SHA-256 input identity for inputs within the scan byte limit. Production
ML scanning binds its `MlReport` to those exact bytes with `with_input`. ML finalization records private
per-reason provenance only for classifier observations matching the report's classified scope and
threshold. A structural rule named `ml.classifier` cannot manufacture that provenance. Legacy reports
without input binding remain accepted as evidence but cannot receive an actionable ML clearance.

The core finalizer rechecks input, scan policy, ruleset, ML report, candidate identity, complete reason
retention, and context sufficiency. It moves only eligible ML reasons to `suppressed`, preserving
severity, span, excerpt metadata, and ML provenance, then recomputes the score from remaining reasons.
Structural reasons and existing suppressions remain in retained analysis. Real coverage gaps survive;
shortened display lists and excerpts do not prevent demotion. A second ML review of the same verdict is refused to preserve review attribution.

The verdict schema adds optional `ml.input_digest`, optional `ml_review` attribution, and the
`ml_review` suppression cause. Old serialized reports remain valid. The report records model, contract
version, request ID, and outcomes in host candidate order. It excludes model-written rationales and
private scope contents. A shortened excerpt remains presentation metadata, independent of coverage.

## Validation and evaluation boundary

`crates/judge/tests/ml_review.rs` covers controlled request/parser/finalizer cases, full-document
rendering, valid and invalid clearances, structural composition, input/provenance binding, real gaps,
truncation, local HTTP transport, duplicate tool/JSON responses, and adversarial property tests.
`crates/cli/tests/contract.rs` validates the new attribution against the published verdict schema.

These tests establish software contract behavior, not whether a live model judges boundaries correctly.
The September 11 dataset results and preserved baseline artifacts remain historical measurements.
The four evaluation arms in the [contract](../specs/006-local-ml-tier/contracts/ml-review.md) still
need captured live responses; an accuracy claim also needs an untouched holdout with exposure exclusions.

Validation on September 11, 2026 passed the workspace suite, all 20 ML review tests (including
property tests and local HTTP servers), CLI/ML/Candle with judge support, both CLI configurations
without judge support, core Wasm compilation, and Clippy with warnings denied both with and without
Candle. Formatter, diff whitespace, core isolation, the 27-crate core dependency allow-list, default
CLI ML isolation, and offline CLI HTTP/TLS exclusion checks also passed. Real-weight inference and
live judge tests were not run; existing absolute fixture release-quality criteria remain unmet.

The workspace suite exposed three cross-document equality assertions: their newly retained input
hashes correctly differed. Those tests now explicitly require different hashes and compare all other
public verdict properties, including every reason, suppression, coverage gap, and policy. Same-input
whole-verdict determinism checks remain unchanged.


### Inference identity and window evidence (2026-09-11)

Successful reports now include a canonical v1 inference identity and ordered per-window scores,
original-input byte envelopes, payload token ranges and model token counts. The whole-document
summary/finding and complete-document review scope remain authoritative; windows do not create
additional findings or release candidates. Identity and window changes invalidate pending review.
Work limits are independent of display limits, and failures never report partial inference as complete.
See `docs/research/inference-and-windowing-2026-09-11.md` and `crates/eval/BOUNDARY.md` for the
identity contract, nested `windowing` configuration, compatibility details and measured limits.
