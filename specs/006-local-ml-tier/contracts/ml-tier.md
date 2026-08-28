# Contract: the ML tier API

**Feature**: `006-local-ml-tier`

---

## Crate boundary

```
please-core ←── please-ml ──→ candle-core, candle-nn, candle-transformers, tokenizers
     ↑                ↑
     │                │
     └── please-judge │
     │                │
     └── please-cli ──┘
```

`please-core` MUST NOT depend on `please-ml`. The arrow is one-way: `please-ml` imports observation types
from `please-core`, and `please-cli` calls both. This boundary is the `#![forbid(unsafe_code)]` guarantee:
everything inside `please-core` is proven safe, and everything inside `please-ml` is the ML runtime's
responsibility.

---

## The loading contract

```rust
/// The only constructor.
///
/// Infallible, for the same reason Engine::builtin() and Judge::new() are: an Err here
/// would tempt a caller into unwrap_or_default and a silent skip, which is a fail-open.
/// The failure surfaces as a TierUnavailable gap in the verdict, not as an Err in the caller's
/// control flow.
pub fn MlModel::load(config: MlConfig) -> MlLoadResult;
```

`MlLoadResult::Unavailable(detail)` is the only failure path. The detail becomes a `CoverageGap` in
the verdict. The caller MUST NOT treat `Unavailable` as `Clean`.

---

## The classification contract

```rust
/// Classify a text segment.
///
/// Returns a probability in [0.0, 1.0], where higher means more likely to be a prompt injection.
/// Returns None if the classifier is not loaded (mode == Embed).
///
/// Long inputs are chunked at the model's context window (512 tokens) with max-score pooling:
/// the returned probability is the maximum across all chunks. This follows Meta's documented
/// recommendation for Prompt Guard 2 and ensures a malicious segment anywhere in a long input
/// is detected.
///
/// Panics: never. An inference error returns 0.0 and records a coverage gap.
pub fn MlModel::classify(&self, text: &str) -> Option<f32>;
```

---

## The embedding contract

```rust
/// Embed a text segment.
///
/// Returns a fixed-dimensional vector (384 for MiniLM-L6, 512 for JinaBERT).
/// Returns None if the embedder is not loaded (mode == Classify).
///
/// Panics: never. An inference error returns a zero vector and records a coverage gap.
pub fn MlModel::embed(&self, text: &str) -> Option<Vec<f32>>;
```

---

## The corroboration contract

An ML classifier label MUST NOT produce a finding on its own. The corroboration requirement is:

| Classifier | Structural finding | Register anomaly | Result |
|---|---|---|---|
| prob ≥ threshold | exists on same segment | any | **Finding** (MlCorroborated) |
| prob ≥ threshold | none | score ≥ anomaly threshold | **Finding** (new observation) |
| prob ≥ threshold | none | score < anomaly threshold | **No finding** |
| prob < threshold | any | any | **No finding** |

This is the false-positive control. A classifier that labels everything as malicious (a broken model, or a
model that overfits to the training distribution) produces no findings without independent corroboration.

The corroboration requirement MAY be relaxed in a future feature if the corpus demonstrates that the
classifier's precision is high enough to stand alone. The relaxation would be a threshold change, not an
architectural change, and it would be gated by a measured false-positive rate.

---

## The re-finalization contract

```rust
/// Merge ML observations into a structural verdict and re-finalize.
///
/// Structural observations are preserved. ML observations are added. The score may increase
/// (new corroborating evidence) but MUST NOT decrease (ML cannot remove structural findings).
///
/// This is a weaker constraint than the judge's "can only narrow": the ML tier can ADD findings
/// (for novel payloads the structural tier missed), while the judge can only confirm or demote
/// existing ones. The difference is justified in plan.md D4: the ML model's weights are
/// operator-controlled and not attacker-influenced, so the amplification risk that constrains
/// the judge does not apply.
pub fn finalize::with_ml(
    structural: Verdict,
    ml_observations: Vec<Observation>,
    ml_report: MlReport,
) -> Verdict;
```

**Invariant**: for any input, `with_ml(v, [], report).score() >= v.score()`. The score is monotonically
non-decreasing. Every structural reason in the input verdict appears in the output verdict. No structural
reason is removed, modified, or reordered.

---

## Thread safety

`MlModel` MUST be `Send + Sync`. One loaded model serves a directory walk across targets. Candle's
`Tensor` is `Send + Sync` by construction (no interior mutability, no thread-local state). The tokenizer
(`tokenizers::Tokenizer`) is `Send + Sync`.

---

## Determinism

The ML tier's verdict-level output is deterministic given the same weights, input, and threshold:

1. The classifier probability is compared against a threshold. The comparison is deterministic.
2. The embedding outlier score is quantized to u16 per-mille. The quantization is deterministic.
3. The corroboration logic is a conjunction of deterministic comparisons.
4. The re-finalization is the same deterministic function as the structural finalization.

Cross-platform variance in intermediate f32 values (SIMD, FMA, denormals) is absorbed by the threshold
comparison and the per-mille quantization. This is the same argument the structural tier makes about
integer arithmetic, extended by one step.

**Exception**: if the platform's f32 arithmetic differs enough to flip a probability across the
threshold boundary (e.g. 0.6999 vs 0.7001), the verdicts will differ. This is inherent to any
threshold-based decision on floating-point data and is recorded in `docs/limits.md`.
