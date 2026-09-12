# Plan: the local ML tier

**Feature Branch**: `006-local-ml-tier`

**Created**: 2026-08-26

**Status**: Draft — architecture decisions. `spec.md` and `tasks.md` follow from these.

**Input**: The eval baseline (`docs/research/eval-baseline.md`) established that sixteen of twenty generated
payloads are unreachable lexically, and their placement makes no difference. The structural tier sees form;
the judge tier (feature 004) sees intent but requires a network call, an API key, and accepts
non-determinism. Neither tier solves the core detection gap offline.

Meanwhile, lightweight transformer classifiers purpose-built for prompt injection detection exist and run
in pure Rust via Candle — an ML framework that builds for `wasm32-unknown-unknown`, supports CPU and GPU
backends, and has BERT, DeBERTa, and embedding model implementations already shipping in production.

**This feature adds a local ML tier that runs offline, deterministically, with no network dependency.**

---

## Summary

A new `crates/ml` crate (`please-ml`) providing two capabilities behind feature gates:

1. **Sequence classification** — a DeBERTa or mDeBERTa classifier scoring text segments as
   malicious / benign, using Candle (pure Rust) or ONNX (faster, native deps) as the inference backend.
2. **Segment embedding** — a small BERT model computing per-segment embeddings for the DocumentMap's
   outlier detection, enabling instruction-data separation without knowing the payload's vocabulary.

Both are opt-in per invocation (`--ml`), both load model weights from a caller-provided path, and both
produce observations that enter the same finalization pipeline as everything else. The default `plz scan`
is unchanged in behaviour, binary size, and dependency count.

---

## Technical Context

| | |
|---|---|
| **Language** | Rust 2021, MSRV as workspace |
| **New crate** | `crates/ml` → `please-ml`, workspace member |
| **Depends on** | `please-core` (for observation types), `candle-core`, `candle-nn`, `candle-transformers`, `tokenizers` |
| **Depended on by** | `please-cli` (feature-gated), `please-eval` (for corpus measurement) |
| **NOT depended on by** | `please-core` — ever. The dependency is one-way |
| **Inference runtime** | Candle (CPU, pure Rust) by default; ONNX behind `ml-onnx` feature |
| **Async** | **None.** Inference is synchronous. One forward pass per segment |
| **Network** | **None at scan time.** Model download is a separate command (`plz ml fetch`) or manual |
| **Placement** | After structural detection, before finalization. Same pipeline position as the judge |
| **Performance** | Default path unchanged. ML path: ~50–150ms per classified chunk |
| **Determinism** | Embedding outlier scores quantized to fixed-point integers: deterministic. Classifier thresholds: configurable, deterministic given the same weights and input |
| **Testing** | Offline: unit tests with small fixture models. Corpus: `please-eval` extended to measure the ML tier |

---

## Architecture Decisions

### D1 — Separate crate, one-way dependency

`please-ml` depends on `please-core` for `Observation`, `DetectionClass`, `Span`, and `Evidence`.
`please-core` MUST NOT depend on `please-ml`. This is the same direction as `please-judge → please-core`
and for the same reason: `please-core` is `#![forbid(unsafe_code)]` and builds for wasm32 without a
model. Candle uses `unsafe` internally. The boundary is architectural, not aspirational.

**Consequence**: the engine does not call the ML tier. The CLI (or any other embedder) calls the ML tier
and feeds its observations into the same `Evidence` accumulator, then hands the accumulator to finalization.
The pipeline in `engine.rs` is unchanged.

### D2 — Two capabilities, independently useful

**Classification** answers: *is this text segment a prompt injection?* This is what DeBERTa and Prompt
Guard do. It catches novel phrasing that no rule anticipates. It is the direct answer to the sixteen
unreachable payloads.

**Embedding** answers: *does this text segment belong with its siblings?* This is the semantic register
feature for DocumentMap. It catches instruction-data boundary violations (the BIPIA problem) where the
payload is benign in isolation. It is the novel contribution.

Both are independently addressable: `--ml-classify`, `--ml-embed`, or `--ml` for both. A deployment
that wants the classifier but not the embedder gets one without paying for the other.

### D3 — Selective inference, not full-document

The ML tier does not scan every byte. It is called on:

1. **Segments with structural observations** — the classifier corroborates or challenges.
2. **Segments the DocumentMap register flags as statistically anomalous** — the classifier labels.
3. **Concealing regions with structural findings** — the classifier adds confidence.
4. **Decoded content that tripped a rule** — the classifier confirms the decoded payload.
5. **Every segment, for embedding** — pairwise similarity is computed within sibling groups.

Category 5 is the only full-document pass, and it is the cheap one (~15ms per segment for MiniLM-L6).
Categories 1–4 are selective: a clean document with no structural signals skips the classifier entirely.

`--ml-full` overrides this and sends every segment to the classifier. This is for batch evaluation, not
for hooks.

### D4 — The classifier can find, not just arbitrate

This is the decision that differs from the judge tier. The judge (feature 004) can only **narrow** —
confirm or demote. It cannot add findings. That constraint exists because the judge is an LLM that reads
attacker-controlled text, and a captured judge that can invent findings is an amplification vector.

**A local classifier is not subject to that constraint.** The model weights are shipped by the operator,
not influenced by the input. The classifier's weights do not change in response to adversarial prompts.
So the ML tier MAY produce new observations for segments that the structural tier found nothing in —
specifically:

- A segment the DocumentMap register flagged as anomalous AND the classifier labels as malicious is a
  **new finding**, not a corroboration. It goes into the evidence accumulator as a new observation with
  detection class `MlClassified` (or `Override` / `AgentDirected` depending on the classifier's label
  granularity).
- A segment the classifier labels as malicious but the structural tier and the register both found
  unremarkable is **not reported**. The classifier alone, without structural corroboration, is not a
  finding. This is the false-positive control.

**The corroboration requirement**: an ML-only finding requires either a structural observation on the
same segment OR a register anomaly score above a threshold. An ML classifier saying "malicious" about
text that looks normal by every other measure is noise, and noise gets the tool switched off.

### D5 — Embedding outlier detection feeds the register, not the verdict

The embedding-based outlier score is a **feature** of the DocumentMap register, not a detection in itself.
It sits alongside `imperative_initial`, `second_person`, `digit_density`, and the other register fields.
The outlier detector uses it; the embedding computation produces it.

This keeps the separation clean: the embedding model computes a number, the register carries it, and the
outlier logic in DocumentMap decides whether it is anomalous — the same logic that handles every other
register field. Adding a new register field is not a new detection class.

### D6 — Model weights are the caller's responsibility

`please-ml` takes bytes (a path to a model directory, or raw SafeTensors data). It does not download
anything at scan time. Model acquisition is:

- `plz ml fetch <model-name>` — a CLI command that downloads from HF Hub and caches locally.
- Manual download — the operator places weights at a known path.
- Embedded — a future optimization where quantized weights are compiled into the binary.

This matches the design of `please-core`: the crate takes bytes, the caller provides them. No network
at scan time means the default path's isolation guarantees are preserved.

### D7 — Determinism by quantization

Classifier inference involves floating-point arithmetic, which is not portably deterministic across
architectures for transcendental functions. However:

- The classifier's output is a probability (a single f32). It is compared against a threshold.
  The comparison is deterministic: `prob >= 0.7` is the same on every platform.
- The embedding outlier score is a cosine similarity (f32). It is quantized to a u16 per-mille
  value before entering the register. The quantization is floor-based and deterministic.

So the **verdict** is deterministic given the same weights, input, and threshold. Two runs on different
platforms may produce different intermediate f32 values but the same final verdict, because the
quantization step absorbs the platform variance.

This is the same argument the structural tier makes about integer arithmetic, extended by one step.

### D8 — Backend feature gates

| Feature | Backend | Dependencies | Performance | Portability |
|---|---|---|---|---|
| `ml-candle` | Candle CPU (pure Rust) | ~42 crates | ~150ms/chunk | everywhere, wasm32 |
| `ml-onnx` | ONNX Runtime | ~20 crates + native lib | ~50ms/chunk | x86_64, aarch64 |
| `ml-cuda` | Candle CUDA | ~55 crates + CUDA toolkit | ~5ms/chunk | NVIDIA GPU |

Default: none. The default `plz` binary carries none of these. `ci/check-cli-dependencies.sh` enforces it.

### D9 — The classifier does not replace the judge

The judge tier (feature 004) answers a different question. The classifier says *"this text looks like
a prompt injection"* — form, like the structural tier, but with a learned vocabulary. The judge says
*"this excerpt is a passenger inside the document, not what the document set out to show"* — intent,
which a classifier cannot express.

Both are useful. A deployment running all three tiers (structural + ML + judge) gets the structural
tier's deterministic baseline, the ML tier's vocabulary-independent classification, and the judge's
intent arbitration. Each can only refine, and `--no-judge --no-ml` reproduces the structural baseline
exactly.

---

## Constitution Check

*GATE: evaluated before Phase 0.*

| Gate | Principle | Status | How it is discharged |
|---|---|---|---|
| Verdict reports; caller enforces | I | PASS | ML observations enter the same accumulator; finalization disposes |
| Incomplete analysis is never clean | I | PASS | A missing model is `TierUnavailable` → `Inconclusive`, like a missing judge. A model that produces no finding is silence, not clearance |
| Optional tier degrades to inconclusive, never clean | I | PASS | Same mechanism as the judge: `IncompleteCause::TierUnavailable` |
| Linear-time analysis | II | PASS | Transformer inference is O(n²) in sequence length, bounded by the 512-token window. Per-document cost is O(segments × window²), which is O(n) for fixed window |
| Bounded input and recursion | II | PASS | The 512-token window is the bound. No recursion in inference |
| No backtracking patterns | II | N/A | This tier uses no regex |
| Rule sets validated against resource limits | II | N/A | This tier uses no rule sets |
| Rules are reviewable data | III | **EXTENDED** | Model weights are opaque — not reviewable in the way rules are. The spec declares this as a **limitation** and compensates with: (a) the model id and digest in every verdict, (b) the classifier never acting alone (D4 corroboration), (c) `--no-ml` reproducing the structural verdict |
| Detection classes independently addressable | III, V | PASS | ML observations carry an existing detection class or a new `MlClassified` class. Addressable like any other |
| Per-source stratified metrics | IV | **REQUIRED** | `please-eval` MUST measure the ML tier per-source, exactly as it measures the structural tier. This is the acceptance gate |
| False-positive gate in CI | IV | **REQUIRED** | The ML tier MUST NOT increase the false-positive rate on any negative slice. Measured, not assumed |
| Gaps stated explicitly | IV | PASS | `docs/limits.md` gains entries for: model opacity, ML non-determinism scope, latency cost, and the corroboration requirement |
| No corpus text vendored | IV | PASS | Model weights are not corpus text |
| **Runtime-free, offline, no model** | V | PASS | The *default* build carries no ML. The *opt-in* build carries no network. Both proven by CI check |
| `wasm32` build proven in CI | V | PASS | `please-core` unchanged. `please-ml` with `ml-candle` builds for wasm32 (Candle does) — proven by a new CI check, not by assertion |
| **Optional deps gated by test** | V | PASS | `ci/check-cli-dependencies.sh` already exists from 004. Extended to cover `please-ml`'s crates |
| CLI holds no logic the library lacks | V | PASS | ML inference is in `please-ml`; the CLI wires flags to it |
| Built-in rule set's validity established | II | PASS | Untouched |
| `forbid(unsafe_code)` in core | V | PASS | `please-core` unchanged. `please-ml` does NOT carry `forbid(unsafe_code)` — Candle requires unsafe. The boundary between the two crates IS the guarantee |
