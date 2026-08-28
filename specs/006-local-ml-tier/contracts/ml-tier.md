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

## The inference contract

```rust
/// Classify a text segment.
///
/// Returns PER-MILLE probability of the malicious class, 0..=1000 — an integer, not the f32 the
/// softmax produced. See "Determinism" below: the quantisation is the argument, not a convenience.
///
/// Long inputs are chunked at the model's context window with MAX-score pooling: the returned
/// value is the highest any chunk reached. Meta's documented recommendation for Prompt Guard 2,
/// and the alternative — mean pooling — lets a long benign document dilute a short payload below
/// any threshold, which is the attack rather than an edge case.
///
/// Panics: never.
pub fn MlModel::classify(&self, text: &str) -> Outcome<u16>;
```

`Outcome` has three arms rather than being an `Option`, because two different failures need to reach
different places:

```rust
pub enum Outcome<T> {
    Ok(T),
    /// The wrong half of the tier was asked. A configuration answer; records nothing.
    NotApplicable,
    /// Inference was attempted and did not produce a usable answer. Records a coverage gap.
    Failed(String),
}
```

The contract originally said an inference error "returns 0.0 and records a coverage gap". **It does not,
and must not.** `0.0` is indistinguishable from a confident verdict of benign, which makes an inference
failure read as a clean segment — a fail-open reachable by malformed input. `Failed` cannot be mistaken
for a score.

---

## The embedding contract

```rust
/// Embed a text segment. 384 dimensions for MiniLM-L6, L2-normalised.
///
/// Panics: never.
pub fn MlModel::embed(&self, text: &str) -> Outcome<Vec<f32>>;
```

Likewise **not** a zero vector on failure, and here the original wording is more dangerous than it was for
`classify`: a zero vector is a *valid-looking* input to cosine similarity, and it scores as maximally
unlike everything. An inference error would manufacture the top outlier in the document.

Embedding **truncates** at the context window where classification **chunks**, and the asymmetry is
deliberate: per-chunk probabilities combine under a maximum with a clear reading, whereas averaging several
chunk vectors produces a point representing none of them. Segments are paragraphs; one past 512 tokens is
rare, and the truncation is recorded as coverage rather than hidden.

---

## The classification contract — what makes a finding

**Superseded (T015). The corroboration requirement below was dropped.** What it required, and why it is
gone, is recorded here rather than deleted, because a safety control that is removed silently is
indistinguishable from one that was never written.

### What it said

An ML classifier label MUST NOT produce a finding on its own. A label above threshold became a finding only
when a structural observation covered the same segment, **or** the segment's embedding outlier score cleared
an anomaly threshold. The stated purpose was false-positive control: a classifier that labels everything
malicious — a broken model, or one that overfits its training distribution — produces no findings without
independent corroboration.

| Classifier | Structural finding | Register anomaly | Result |
|---|---|---|---|
| prob ≥ threshold | exists on same segment | any | ~~Finding (MlCorroborated)~~ |
| prob ≥ threshold | none | score ≥ anomaly threshold | ~~Finding (new observation)~~ |
| prob ≥ threshold | none | score < anomaly threshold | ~~No finding~~ |
| prob < threshold | any | any | ~~No finding~~ |

### Why it was dropped

T008 measured the second signal. As a document-level detector the embedding outlier score reaches a **3.1%**
true-positive rate at zero false positives, against `document-map.md` §6's kill criterion of **25%**, and the
positive and negative distributions overlap at every quartile — on the hand-written fixtures the negatives
score *higher* than the positives. §6's instruction for a failed M2 is *abandon rather than tune*.

That kills row 2, and row 2 was the only row that could produce a finding the structural tier had not already
produced. Keeping the table without it leaves a tier that can only confirm what the rules already found —
which reaches none of the sixteen generated payloads the rules cannot phrase, and those payloads are the
entire reason this feature exists (US1, SC-601).

The choice was therefore between a tier that cannot meet its own success criterion and a tier with one less
layer of defence. **The requirement was dropped**, deliberately and on the record.

### What the rule is now

```
prob >= threshold  ->  Finding
prob <  threshold  ->  No finding
```

The comparison is inclusive at the threshold. The embedding outlier score is **reported in `MlSegmentResult`
and gates nothing** — `crates/ml/src/outlier.rs` states that at its definition, and no code in `please-ml` or
`please-core` compares it against a threshold.

### What now controls false positives

The threshold and SC-602's regression check, and nothing else. Three consequences follow, and they belong in
`docs/limits.md` rather than only here:

1. **A model that overfits produces findings directly.** The compensating control is gone. `--ml` being
   opt-in, and `--no-ml` reproducing the structural verdict exactly, are what remain.
2. **The threshold is per-model and not portable.** T002 measured ProtectAI scoring an ordinary imperative —
   *"Please translate the customer email into French"* — at 388 per-mille, so no threshold below ~400 is
   available on that model at all. T003 measured Prompt Guard 2 scoring the same class of text at 4. A
   default tuned for one is wrong for the other by two orders of magnitude.
3. **SC-602 is now a gate, not a checkbox.** It decides whether this tier may ever be on by default. Until
   it has run against the corpus, `--ml` stays opt-in.

Severity is a bounded ramp rather than the probability itself (`crates/ml/src/observe.rs`): a finding at
threshold scores 40, one at 1000 scores 75, and the ceiling sits below the structural tier's maximum of 90.
A rule an operator can read outranks a model nobody can — Principle III in arithmetic. The constants are
chosen, not calibrated, the same admission `score.rs` makes about its own.

### If corroboration comes back

It would need a second signal that measures better than the one that failed, and the number to beat is §6's
25%. It would be a threshold change rather than an architectural one: `observe()` is the single place a
probability becomes an observation.

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
    bounds: Bounds,      // added in T017
    bands: &Bands,       // added in T017
) -> Verdict;
```

**Invariant**: for any input, `with_ml(v, [], report).score() >= v.score()`. The score is monotonically
non-decreasing. Every structural reason in the input verdict appears in the output verdict. No structural
reason is removed or modified.

Two corrections to the above, both found while implementing it:

* **Reasons ARE reordered, and must be.** The contract said "not reordered". Reasons are ordered by byte
  offset (FR-125), and an ML finding at offset 5 belongs between structural findings at 0 and 20. Appending
  instead would make output depend on which tiers ran, breaking SC-011's byte-identical guarantee for every
  scan that used `--ml`. What must not change is the *set* of structural reasons, and that is what the test
  asserts.
* **The two extra arguments are what the invariants require.** `bands` because the score moves and has to
  be re-banded against the table the scan used, not a default — `rejudge` takes it for the same reason.
  `bounds` because ML observations must cross the same excerpt-sanitisation boundary structural ones do; a
  second entrance that skipped it would be a second entrance for unneutralised attacker text.

**A truncated verdict is refused**, exactly as `rejudge` refuses one (plan D9). `finalize` aggregates the
score before truncation, so once a `Verdict` exists the severities past `max_reasons` are gone; recomputing
from the survivors would *lower* the score while claiming to have added evidence. The refusal records a
`TierUnavailable` gap and attaches no report — `ml()` staying `None` is what says the tier did not act.

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
3. There is no corroboration logic left to be deterministic about; a single threshold comparison decides
   a finding.
4. The re-finalization is the same deterministic function as the structural finalization.

Cross-platform variance in intermediate f32 values (SIMD, FMA, denormals) is absorbed by the threshold
comparison and the per-mille quantization. This is the same argument the structural tier makes about
integer arithmetic, extended by one step.

**Exception**: if the platform's f32 arithmetic differs enough to flip a probability across the
threshold boundary — after per-mille rounding, i.e. 699 vs 700 — the verdicts will differ. The
quantisation narrows the window in which this is possible but does not close it. This is inherent to any
threshold-based decision on floating-point data and is recorded in `docs/limits.md`.
