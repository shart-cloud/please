# Versioned inference identity and window reporting — 2026-09-11

Implementation of slices 1–4 of [the plan](inference-and-windowing-plan-2026-09-11.md), with local
exploratory measurement documented separately below. Shipping overlap remains zero.

## Attribution and loading

Successful ML reports add `inference: {version, digest, fields}` and `windows`. The legacy `digest`
continues to mean the weights SHA-256; model name/revision remain provenance claims. Inference fields
cover the weight/config/tokenizer bytes, architecture/kind, malicious label, context size, overlap,
preprocessing/pooling/rounding recipe, CPU/F32 backend, and a build fingerprint. Canonical v1 hashing
uses a domain prefix, field count, sorted UTF-8 keys and values, and u64 big-endian byte lengths.
It never hashes Rust debug output or depends on map insertion order.

The build fingerprint covers ML/core sources, manifests, both repository lockfiles, the build script,
toolchain version, target configuration, enabled ML features and compilation settings. It is
conservative: unrelated lockfile changes can invalidate identity. It captures this repository build,
including uncommitted source; it is not a cryptographic attestation of arbitrary patched dependency
sources or every possible external toolchain/environment modification. Experiment metadata also
records the evaluator executable digest and runtime host details.

Tokenizer/config are parsed from the same buffers that are hashed. Weights are hashed and loaded
through the same mapping and Candle's slice loader, avoiding a second full-file allocation and
preventing a pathname replacement from redirecting a later open. Tensor construction copies into
owned CPU storage. Artifacts must remain unchanged during loading: concurrent modification of the
mapped file is unsupported. Read-only access by the scanner does not make a writable external file
immutable. No claim of protection against such concurrent writes is made.

Threshold, impact and work limits are decision/run settings, separate from raw inference identity.
Paths and provenance aliases likewise do not alter raw inference identity. Product `run.json` v3
records inference identity and work limits and rejects reuse across different configurations.
Historical reports without identity stay unrecorded. Existing constructors/score accessors remain.
Direct Rust `MlConfig` literals now need `windowing: Default::default()` or explicit settings.

Judge metadata now derives from the same effective request-recipe builders used for transport:
model, prompt/tool recipe digests, generation settings, timeout, authority and the resolved endpoint
hash. Only a digest of the endpoint is published because URL paths/queries can contain credentials.
Provider model weights remain unrecorded; remote reproducibility is not implied.

## Window evidence and budgets

`classify_detailed()` returns ordered original-input window spans, payload token ranges, model token
counts, raw per-mille scores, the maximum and earliest winning window. `classify()` delegates to this
path and returns the maximum. Reports keep the original whole-document summary and one ML observation;
window evidence does not multiply findings or create new review candidates. It does not change impact
or add structural class breadth. Byte envelopes describe tokenized regions, not precise attack spans.

Window arrays use shared immutable storage in core reports, so report provenance/review cloning does
not copy the whole array repeatedly. Display limits never remove retained window evidence. Inference
identity and window contents participate in report equality and therefore stale-review rejection.

Configuration accepts a nested `windowing` object: `overlap_tokens` defaults to zero, `max_windows`
to 4096 and `max_total_tokens` to 2097152. Overlap is in payload tokens, smaller than capacity after
special-token reservation. Work counts repeated payload and special tokens and is checked before
window expansion/inference. Input tokenization still processes the complete caller-bounded document;
these are work limits, not elapsed-time deadlines. A failed window invalidates this ML attempt and
adds a gap while retaining structural evidence; partial results never masquerade as a complete scan.

## Evaluation and limits

See [boundary evaluation](../../crates/eval/BOUNDARY.md) for capture-compatible seeds, deterministic
freezing, verification, real inference, outputs and reproduction. The runner uses shared config and
`ScanSession`, enforces tokenizer/context identity, records per-window output and separates ML
admission from product decisions. Grouped bootstrap intervals are descriptive, not evidence that
small authored fixtures satisfy deployment targets. Normal CI includes tokenizer-only placement and
metric tests without fetching weights. The historical mechanism gate retains its separate meaning.

Numeric product runtime budgets and an independently governed holdout are still required before
selecting a new shipping default. No paid/provider calls or remote judge measurement were made.

## Validation evidence

Workspace tests with CLI Candle passed (`/tmp/bee-window-workspace-final.log`), including new identity
and window review-binding tests and credential-free judge recipe metadata checks. CLI tests without
default features passed (`/tmp/bee-window-offline.log`). The evaluator passed tests with both shipping
tiers (`/tmp/bee-boundary-eval-final.log`); the final prose-carrier generation passed its tokenizer-only
integration suite (`/tmp/bee-boundary-tests-v2.log`). Workspace Clippy and evaluator Clippy with default,
tokenizer-only and both shipping features passed with warnings denied. Formatting and dependency
isolation checks passed; core remains at its exact 27-crate normal-dependency baseline.

Pinned-cache verification passed for ProtectAI. The real tokenizer differential check passed against
native zero-overlap preprocessing. All nine real-weight regressions passed, including detailed window
maximum/span checks, and the real CLI/schema/evidence-preservation smoke test passed. Evidence:
`/tmp/bee-boundary-assets.log`, `/tmp/bee-window-tokenizer.log`, `/tmp/bee-window-real.log`, and
`/tmp/bee-window-real-cli.log`. These are actual local inference checks, separate from mocked tests.

The fresh offline mechanism gate passed: benign fixtures 1/20, matched negatives 0/14, repository prose
16/75, against its recorded regression limits (`/tmp/bee-window-mechanism-final.log`). Those rates still do
not establish the 1% target. The overlap development measurement uses separate frozen inputs,
identities and operating-point settings; it cannot inherit this mechanism gate's baselines.


## Local development sweep

[The completed measurement](window-boundary-measurement-2026-09-11.md) compares all four overlaps on
47 frozen prose-carrier cases. All settings detected 21/21 attacks. Nonzero overlap reduced benign
flags from 6/26 to 5/26; larger overlaps added cost without improving the aggregate counts. The
63-token setting and the larger overlaps clear different cases, as recorded in the paired results.
This is explicitly authored development data, including a documented discarded carrier pilot.
It does not establish the 1% target or justify changing the zero-overlap shipping default.

The real CLI and the evaluator produced equal inference identities for the same zero-overlap model
configuration. The measurement stores the executable digest, per-run recipe/work settings, every
window score and span, and paired decision changes. Held-out operating-point selection and numeric
product runtime budgets remain outstanding. No remote judge was called.
