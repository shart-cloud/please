# Tasks: the local ML tier

**Feature Branch**: `006-local-ml-tier`

**Status**: Draft — task breakdown. Depends on [plan.md](./plan.md) and [spec.md](./spec.md).

---

## Phase 0 — Research and feasibility (before writing any production code)

### T001 — Candle dependency measurement

Resolve `candle-core`, `candle-nn`, `candle-transformers`, and `tokenizers` in a scratch workspace member.
Measure exact crate count, build time, and binary size for CPU-only, ONNX, and CUDA configurations.
Verify the `wasm32-unknown-unknown` build for the CPU configuration. Record in `research.md` R1.

**Acceptance**: the dependency table in R1 has measured numbers, not estimates. The wasm32 build either
succeeds or the research records why and what it would take.

**Done.** [research.md R1](./research.md#measured-t001). Measured, not estimated: `candle-core` alone is
**119** crates (estimate said ~35), the full stack **129** (~42), and `--features ml` on `please-eval`
costs **+112 crates**, +6.5 MiB of binary and +119 s of clean build. No `tokio`; `rayon` does arrive via
`tokenizers`.

**wasm32 does not build as R1 originally claimed**, and the correction is actionable for SC-609/T042: it
needs `getrandom` with `wasm_js` as a *direct* dependency, `RUSTFLAGS='--cfg
getrandom_backend="wasm_js"'`, and `tokenizers` selected with `unstable_wasm` rather than `onig` (whose
`onig_sys` C build script has no wasm toolchain). With all three, the full stack builds in 39.6 s.

### T002 — DeBERTa inference proof-of-concept

Load `ProtectAI/deberta-v3-small-prompt-injection-v2` in a Candle `BertModel` (DeBERTa is architecturally
close). Tokenize a known injection string and a known benign string. Forward pass on CPU. Assert the
injection scores above 0.7 and the benign scores below 0.3.

**Acceptance**: a test in the scratch workspace that loads real weights, runs a forward pass, and prints
both probabilities. No mock.

**Done, acceptance partially met.** `please-eval model smoke protectai-deberta-v3-small`. Real weights,
real forward pass, no mock. Injection scores **1.0000** — clears the >0.7 bar. But the benign ceiling is
**0.3882**, above the <0.3 the acceptance asked for: *"Please translate the customer email into French
and preserve its formatting."* is an imperative, and the classifier reads it as one.

Not a blocker at the proposed 0.7 threshold — the separation margin is 0.6118 — but it is the shape of
SC-602's risk, and it means no threshold below ~0.4 is available on this model. Recorded rather than
softened.

### T003 — Prompt Guard 2 inference proof-of-concept

Same as T002, for `meta-llama/Llama-Prompt-Guard-2-86M`. This uses mDeBERTa-base, which may need
additional Candle support or an ONNX path.

**Acceptance**: same as T002, or a recorded decision that this model requires the ONNX backend with
rationale.

**Done, acceptance fully met, and the ONNX question is closed.** Prompt Guard 2 86M loads in Candle's
`debertav2` module with no additional support and no ONNX path: injections **0.9979 / 0.9996**, benigns
**0.0004 / 0.0004**, separation margin **0.9974** against ProtectAI's 0.6118.

It is the better classifier by a wide margin and the more expensive one on every axis: 2.3 s to load,
**444 ms** per inference (the slowest of the three despite the fewest parameters — see R6), a 1.08 GiB
download, and a gated Llama 4 Community License. R2's "what each tier buys" now has numbers behind it.

### T004 — MiniLM-L6 embedding proof-of-concept

Load `sentence-transformers/all-MiniLM-L6-v2`. Embed three sentences: two semantically similar, one
different. Assert cosine similarity between the similar pair is > 0.8 and between each and the outlier
is < 0.5.

**Acceptance**: a test that loads real weights and computes real embeddings. The cosine similarities are
printed and asserted.

**Done, acceptance not met as written.** Real weights, real embeddings, 384 dimensions. The outlier
separation is emphatic — the unrelated sentence scores **-0.0014** and **-0.0058** against the required
<0.5. But the *similar* pair scores **0.6485**, below the >0.8 this task asked for and below the >0.7
T013 asks for.

The threshold was optimistic rather than the model being broken: ~0.65 is an ordinary all-MiniLM-L6-v2
value for a loose paraphrase ("A dog is playing outside in the garden." / "A puppy runs and plays in the
yard."). **T013's >0.7 acceptance should be restated against a measured baseline before it is written**,
or it will fail for the same reason. This does not affect SC-603, which ranks *relative* similarity
within a document and never compares against an absolute threshold.

### T005 — Latency measurement

Measure inference latency for all three models on CPU (no GPU) over the five scenarios in research.md R6.
Record in a table with the machine spec.

**Acceptance**: the table in R6 has measured numbers. Each entry is a median of 10 runs.

**Done.** [research.md R6](./research.md#measured-latency-t005). Medians of ten warm runs, `--release`,
i9-12900HK: ProtectAI **183.3 ms**, Prompt Guard **443.9 ms**, MiniLM **34.2 ms**; loads 795 ms / 2298 ms
/ 52 ms.

Candle on x86 is **slower than the ~50–150 ms** this feature was scoped against — those figures came from
`parry-guard` on Apple Silicon. Two consequences: FR-652's selective inference is load-bearing rather
than an optimisation (a 60-chunk `--ml-full` megabyte is ~11 s on ProtectAI and ~27 s on Prompt Guard),
and R1's ONNX backend stops being optional if the classifier is ever to run on more than a few segments.

### T006 — Kill-criterion measurement for embedding outlier detection

Run the MiniLM-L6 embedder over the generated corpus's 1,060 rows. For each row with ≥3 segments of the
same kind, compute pairwise cosine similarity within the sibling group. Record the rank of the injected
segment's outlier score. If the injected segment is the top outlier on fewer than 50% of qualifying rows,
record the kill criterion as failed and do not proceed with the embedding approach.

**Acceptance**: a number. SC-603 says ≥60% to ship, ≥50% to keep experimenting, <50% to abandon.

**Done.** `please-eval model outlier` (`crates/eval/src/segment.rs`, `src/outlier.rs`, `src/ml.rs`).
951 of 1,060 rows scoreable; **top-1 55.6%, top-3 80.3%** → **continue**. Full stratification in
[`docs/research/embedding-outlier-results.md`](../../docs/research/embedding-outlier-results.md),
reading in [research.md R3](./research.md#measured-t006).

Three things it changed for the tasks below:

* **T014 is not cancelled and not cleared.** `continue` means the embedding half stays an experiment.
  Do not write T013–T015 as production code on the strength of this number.
* **SC-603 and `document-map.md` §6 M1 state different criteria** — top-1 versus top-3 — and disagree
  about the answer on this corpus. `spec.md` cites the memo as though they agreed. That is a spec
  defect to resolve before T033 gates on either.
* **The constraint is sibling homogeneity, not payload isolation.** 68.9% top-1 on payloads that became
  their own segment against 13.2% where they shared one — but see T007: the obvious fix for that gap was
  tested and made the number worse.

### T007 — Sub-segment granularity (added after T006)

Test the reading T006's placement split invites: that cutting prose finer moves the `diluted` population
into `isolated` and raises the overall rate. One flag on the existing command, so the corpus, the model
and the scoring are held identical.

**Done, hypothesis falsified.** `model outlier --sentences`. Over the 951 rows scored under both,
top-1 goes **55.6% → 51.9%** and top-3 **80.3% → 78.1%**; 28 rows fixed, 63 broken. It gains where
predicted (`post-signature` +5.0, `mid-paragraph` +2.8) and loses more where it was already working
(`trailing` −10.9, `prepend` −8.7, `post-gap` −7.5).

The mechanism is the point: `isolated` rows fell 68.9% → 63.8% with nothing about those payloads
changed. Their siblings got finer, and a group of many short fragments has a higher noise floor than a
group of few long ones. **The bound is sibling homogeneity, not payload isolation** —
[research.md R3](./research.md#sub-segment-granularity--measured-and-it-makes-things-worse).

**Acceptance**: a number for both granularities from one command, and the losing option is not deleted.
`--sentences` stays so the comparison is re-runnable when the corpus or the model changes.

### T008 — M2 and M7: the detector question, and the held-out check (added after T007)

`document-map.md` §4 defines M7 as **M1 and M2** on the hand-written fixtures with the threshold frozen
from generated data. Running it required M2 first — the document-level separation metric SC-603's
ranking work had skipped.

**Done. M2 fails §6's kill criterion decisively.** `please-eval model holdout`, full report in
[`docs/research/embedding-separation-results.md`](../../docs/research/embedding-separation-results.md).

| metric | criterion | measured |
|---|---|---:|
| M2, zero FPR on the 14 matched negatives | ≥25% (§6) | **3.1%** (32/1030) |
| M2, zero FPR on all 90 negatives incl. security prose | ≥25% (§6) | **2.9%** (30/1030) |
| M7, same threshold, held-out fixtures | — | 0.0% (0/20) |

The positive and negative score distributions overlap at every quartile — on the hand-written set the
**negatives score higher** (median 901) than the positives (864). Every document has a
most-unlike-its-siblings segment whether or not one was injected, so the magnitude of that oddness
carries no information about whether the document is hostile. M1's 55.6% and M2's 3.1% are the same
score answering different questions, and are not in tension.

**M7 itself is uninformative and the report says so** rather than reporting 3.1% → 0.0% as "no cliff".
A held-out check tells you whether a signal transfers; it cannot manufacture one.

Consequences for the tasks below:

* **T014 (outlier score) and the embedding half of T015 should not be written as a detector.** §6's
  response to a failed M2 is *abandon rather than tune*.
* **D4's corroboration framing survives on its own terms** — the spec never had the outlier score fire
  alone. Whether §6's criterion governs that narrower job is a spec decision, not a measurement.
* **T033's remaining work shrinks further.** If the embedding tier is not shipped as a detector, SC-603
  is a research number rather than a gate.

**Blocked half**: M7's M1 cannot be computed. None of the 51 injection fixtures carries an
`injected_span`; the field exists on generated rows only. Span-labelling them is the unblock, and it
would also give the shipped structural detectors a held-out span-localisation number that
`crates/eval/src/metrics.rs` already knows how to compute and has never had.

**Acceptance**: M2 and M7 measured, reported per slice with the unscoreable denominators visible, and
the §6 verdict computed rather than asserted.

---

## Phase 1 — The `please-ml` crate

### T010 — Crate scaffold

Create `crates/ml` as a workspace member. `Cargo.toml` with:
- `candle-core`, `candle-nn`, `candle-transformers` behind `candle` feature
- `tokenizers` (always, needed for both backends)
- Depends on `please-core` for `Observation`, `Span`, `DetectionClass`, `Evidence`
- Does NOT carry `#![forbid(unsafe_code)]`

Add `please-ml` to `ci/check-cli-dependencies.sh` exclusion: the default CLI must not pull it in.

**Acceptance**: `cargo check -p please-ml` succeeds. `ci/check-cli-dependencies.sh` passes.

### T011 — `MlModel` and the loading contract

Implement `MlModel::load(config)` returning `MlLoadResult`. Load tokenizer from `tokenizer.json`, weights
from `model.safetensors` (or `*.onnx`), in the directory `config.model_path` points at. Every failure is
`Unavailable(detail)`, never a panic.

**Acceptance**: a test loading a model from a valid path succeeds. A test loading from `/dev/null` returns
`Unavailable`. A test loading from a directory with a corrupt safetensors file returns `Unavailable` with
the cause.

### T012 — Classifier: tokenize, forward, probability

Implement `MlModel::classify(text) -> f32`. Tokenize with the loaded tokenizer, pad/truncate to the
model's max length, forward pass through the loaded model, softmax the logits, return the probability of
the malicious class.

Chunking for long inputs (FR-612): if the tokenized input exceeds the model's context window (512 tokens),
split into chunks and return the maximum probability across chunks.

**Acceptance**: the proof-of-concept from T002 is a test in `crates/ml/tests/`. Classifier probability for
a known injection is ≥ 0.7. Classifier probability for known benign text is ≤ 0.3.

### T013 — Embedder: tokenize, forward, pool

Implement `MlModel::embed(text) -> Vec<f32>`. Tokenize, forward pass, mean-pool the last hidden layer.

**Acceptance**: the proof-of-concept from T004 is a test in `crates/ml/tests/`. Cosine similarity between
two similar sentences is > 0.7.

### T014 — Outlier score computation

Implement `compute_outlier_scores(segments: &[(Span, &str)], model: &MlModel) -> Vec<(Span, u16)>`.
Embed each segment, compute pairwise cosine similarity within the group, return the per-mille outlier score
for each (1000 - mean_similarity_to_siblings * 1000), quantized to u16.

**Acceptance**: a test with a group of 5 segments (4 similar, 1 different) ranks the different one as the
top outlier.

### T015 — Observation builder

Implement a function that takes a classifier probability, an outlier score, a structural observation
(optional), and the ML config, and returns an `Option<Observation>`. The corroboration requirement (D4):

- Classifier prob ≥ threshold AND structural observation exists → observation with `MlCorroborated`
- Classifier prob ≥ threshold AND outlier score ≥ anomaly threshold → new observation
- Classifier prob ≥ threshold alone → `None`
- Classifier prob < threshold → `None`

**Acceptance**: unit tests covering all four cases.

### T016 — `MlReport` type

Add `MlReport` and `MlSegmentResult` to `please-core`'s verdict types (in `finalize::types`). Add
`Option<MlReport>` to `Verdict`. These are data types only — `please-core` does not depend on `please-ml`,
it just carries the report struct.

**Acceptance**: `Verdict` round-trips through JSON with and without `ml` populated.

### T017 — `finalize::with_ml`

Add a function in `please-core::finalize` that takes a structural verdict and a list of ML observations,
merges them into the evidence, and re-finalizes. The structural observations are preserved; the ML
observations are added. The score may increase; it may not decrease.

**Acceptance**: a test where the structural verdict has score 50 and two ML observations are added.
The merged verdict's score is ≥ 50. The structural reasons are unchanged.

---

## Phase 2 — CLI integration

### T020 — `--ml` flag and model loading

Add `--ml`, `--ml-classify`, `--ml-embed`, `--ml-full`, `--ml-threshold`, `--model-path`, and `--ml-model`
to `plz scan`. When `--ml` is passed, load the model at startup (FR-651: once per process). When the model
is unavailable, record a `TierUnavailable` gap (FR-603).

**Acceptance**: `plz scan --ml skill.md` loads the model and runs classification. `plz scan skill.md`
does not.

### T021 — Selective inference integration

After `engine.scan()` returns the structural verdict:
1. Extract segments from the input.
2. For segments with structural findings or high register anomaly, run the classifier.
3. Compute embeddings for all segments and derive outlier scores.
4. Build ML observations for corroborated findings.
5. Call `finalize::with_ml()` with the merged evidence.

**Acceptance**: a structural finding corroborated by the classifier produces a higher score than the
structural finding alone.

### T022 — `plz ml fetch` and `plz ml list`

Add the `ml` subcommand with `fetch` and `list`. `fetch` downloads from HF Hub using the `hf-hub` crate,
authenticating with `HF_TOKEN`. `list` prints cached models with digests.

**Acceptance**: `plz ml fetch deberta-v3-small` downloads the model. `plz ml list` shows it.

### T023 — JSON output with ML report

When `--ml` is active and `--format json` is used, the verdict JSON includes the `"ml"` key described in
`data-model.md`.

**Acceptance**: JSON output validates against an extended schema. The `ml` key is absent when `--ml` is
not passed.

### T024 — `--explain` with ML findings

Under `--explain`, ML-originated findings show the classifier probability, the outlier score, and the
corroboration source.

**Acceptance**: `plz scan --ml --explain` shows all three for an ML finding.

---

## Phase 3 — Evaluation

### T030 — `please-eval` extended for the ML tier

Add an `--ml` flag to `please-eval run`. When enabled, each corpus row is scanned with the ML tier active.
Per-source metrics are reported separately for structural-only and structural+ML, so the delta is visible.

**Acceptance**: `please-eval run --ml && please-eval report` produces a table with both columns.

### T031 — SC-601: detect unreachable payloads

Run `please-eval` with `--ml` on the generated corpus's 1,060 rows. Count how many of the sixteen
previously-unreachable payloads are now detected.

**Acceptance**: ≥4 newly detected. This is the criterion the tier exists for.

### T032 — SC-602: false-positive regression check

Run `please-eval` with `--ml` on `neg_orbench`, `neg_multilingual`, and `neg_nonadversarial`. Assert
false-positive rates do not increase.

**Acceptance**: each slice's FP rate with `--ml` is ≤ the baseline without `--ml`.

### T033 — SC-603: embedding outlier precision

Already reproducible and already in `please-eval` — T006 built it there rather than in a scratch
workspace, so what is left here is the gate, not the measurement.

**Blocked on a spec decision**: SC-603 says top-1, `document-map.md` §6 M1 says top-3, and at 55.6% /
80.3% the two disagree. Gating on either without resolving that is picking the kinder number after
seeing it.

**Acceptance**: `model outlier` exits non-zero below the agreed floor, and the floor is written down
in one place that both documents point at.

### T034 — SC-608: multilingual false-positive rate

Run Prompt Guard 2 86M on the 7,211 non-English negative rows. Assert FP rate ≤ 0.6%.

**Acceptance**: the measured rate, reported in `docs/limits.md`.

---

## Phase 4 — Documentation and limits

### T040 — `docs/limits.md` entries

Add entries for:
- Model opacity (Principle III gap — weights are not reviewable like rules)
- The corroboration requirement and what it costs (a malicious segment with no structural or register
  signal is not reported)
- Latency cost of `--ml`
- The embedding outlier score's kill criterion result
- Cross-platform determinism scope (quantization absorbs float variance)

### T041 — `docs/rules.md` extended

Document the `--ml` flags, the `plz ml` subcommand, and how the ML tier interacts with `--judge`.

### T042 — CI gates

- `ci/check-cli-dependencies.sh` extended to cover `please-ml` crates
- `ci/check-ml-wasm32.sh` new: proves `please-ml` with `ml-candle` builds for wasm32
- `please-eval gate` extended with ML-tier regression floors
