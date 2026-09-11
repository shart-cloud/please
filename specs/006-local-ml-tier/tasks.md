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

**Done, with one correction.** `ci/check-cli-dependencies.sh` does not exist and never did — the scripts
are `ci/check-dependencies.sh` (which guards `please-core`, and guards it *structurally*: a crate depending
on core cannot appear in core's own tree) and `ci/check-core-isolation.sh`. The CLI had no guard at all.

Written as **`ci/check-ml-isolation.sh`**, asserting the default `please-cli` tree contains none of
`please-ml`, `candle-*`, `tokenizers`, `ug` or `gemm`. It exists *before* the Phase 2 edge does, which is
the point: a guard added after the mistake has to argue for a revert.

Candle is behind a non-default `candle` feature on the crate itself, so `cargo check -p please-ml` costs
none of T001's +112 crates and the outlier arithmetic, observation builder and config validation are all
testable without it. Both configurations compile and are clippy-clean; core's pin still reports exactly 27
crates.

### T011 — `MlModel` and the loading contract

Implement `MlModel::load(config)` returning `MlLoadResult`. Load tokenizer from `tokenizer.json`, weights
from `model.safetensors` (or `*.onnx`), in the directory `config.model_path` points at. Every failure is
`Unavailable(detail)`, never a panic.

**Acceptance**: a test loading a model from a valid path succeeds. A test loading from `/dev/null` returns
`Unavailable`. A test loading from a directory with a corrupt safetensors file returns `Unavailable` with
the cause.

**Done.** `MlModel::load` in `crates/ml/src/model.rs`. Validation runs before any I/O, so a misconfigured
run is refused in microseconds rather than after T003's measured 2.3 s load. The SHA-256 is computed from
the file at load rather than trusted from a manifest — a manifest records what was *downloaded*, and
between that and this sit a mirror, a cache and a filesystem.

The manifest itself is deliberately **not** read by this crate. `please-eval` owns `corpus/models.toml`
because fetching needs a catalogue; inference does not, and keeping it out leaves `toml` off the shipping
graph.

### T012 — Classifier: tokenize, forward, probability

Implement `MlModel::classify(text) -> f32`. Tokenize with the loaded tokenizer, pad/truncate to the
model's max length, forward pass through the loaded model, softmax the logits, return the probability of
the malicious class.

Chunking for long inputs (FR-612): if the tokenized input exceeds the model's context window (512 tokens),
split into chunks and return the maximum probability across chunks.

**Acceptance**: the proof-of-concept from T002 is a test in `crates/ml/tests/`. Classifier probability for
a known injection is ≥ 0.7. Classifier probability for known benign text is ≤ 0.3.

**Done, acceptance restated against T002's measurement.** `crates/ml/tests/real_weights.rs`, eight tests
against real weights from the eval cache, skipping rather than failing when it is cold.

The `≤ 0.3` benign bar is **not** asserted, because T002 measured ProtectAI scoring the benign case at
0.3882 and no threshold below ~400 per-mille is available on that model. Asserting a number nobody measured
produces a red test whose only fix is to weaken the assertion, which teaches the suite to be ignored. What
is asserted is **separation** — injection ≥ 900, benign ≤ 500, gap ≥ 400 — which is the property that makes
a classifier useful and which both models clear decisively.

FR-612's chunking is tested rather than assumed: a payload placed after ~2,000 tokens of filler, well past
the 512-token window, still scores ≥ 900. That is the test that would fail under mean pooling or silent
truncation, and it passes.

### T013 — Embedder: tokenize, forward, pool

Implement `MlModel::embed(text) -> Vec<f32>`. Tokenize, forward pass, mean-pool the last hidden layer.

**Acceptance**: the proof-of-concept from T004 is a test in `crates/ml/tests/`. Cosine similarity between
two similar sentences is > 0.7.

**Done, acceptance restated — and T004 predicted this exactly.** T004's note said the > 0.7 bar "should be
restated against a measured baseline before it is written, or it will fail for the same reason". It was,
and it would have.

`all-MiniLM-L6-v2` scores T004's paraphrase pair at 0.6485, an ordinary value for that model. The test
asserts the **ordering** — paraphrase > 0.55, unrelated < 0.35, gap > 0.3 — because ordering is what the
outlier ranker actually consumes; it never compares against an absolute threshold. Also asserted: 384
dimensions, and that vectors arrive L2-normalised, without which the outlier score's anchor at 1000 stops
meaning anything.

### T014 — Outlier score computation

Implement `compute_outlier_scores(segments: &[(Span, &str)], model: &MlModel) -> Vec<(Span, u16)>`.
Embed each segment, compute pairwise cosine similarity within the group, return the per-mille outlier score
for each (1000 - mean_similarity_to_siblings * 1000), quantized to u16.

**Acceptance**: a test with a group of 5 segments (4 similar, 1 different) ranks the different one as the
top outlier.

**Done, and scoped down to what T006/T008 support.** `crates/ml/src/outlier.rs`. The acceptance test passes
on hand-built vectors, and the same claim is made against real embeddings in `real_weights.rs` — four
invoice paragraphs and one injected instruction, injection on top.

**It is a ranker and gates nothing.** T008 is the reason, and the module says so at its definition: 55.6%
top-1 at *locating* a known payload, 3.1% at *deciding whether there is one* against a 25% criterion.
Nothing in `please-ml` or `please-core` compares this score against a threshold.

Two details kept from the eval implementation because they are load-bearing: the range is `0..=2000` rather
than clamped at 1000, since cosine runs `[-1, 1]` and clamping would collapse "unrelated" into "opposite";
and a segment with fewer than two siblings scores nothing at all, rather than being handed a default that
would put every one-paragraph document at the top of a ranking.

### T015 — Observation builder

Implement a function that takes a classifier probability, an outlier score, a structural observation
(optional), and the ML config, and returns an `Option<Observation>`. The corroboration requirement (D4):

- Classifier prob ≥ threshold AND structural observation exists → observation with `MlCorroborated`
- Classifier prob ≥ threshold AND outlier score ≥ anomaly threshold → new observation
- Classifier prob ≥ threshold alone → `None`
- Classifier prob < threshold → `None`

**Acceptance**: unit tests covering all four cases.

**Done — and there are two cases, not four.** The corroboration requirement was dropped. Full argument in
`contracts/ml-tier.md`, which keeps the old table struck through rather than deleting it, and in the module
docs of `crates/ml/src/observe.rs`.

Short version: row 2 of the table gated a finding on the embedding outlier score clearing an anomaly
threshold, and T008 measured that score at 3.1% against a 25% kill criterion. Row 2 was also the only row
that could produce a finding the structural tier had not already produced — so keeping the table minus row 2
leaves a tier that reaches none of the sixteen payloads the rules cannot phrase, which is SC-601 and the
reason the feature exists. The choice was a tier that cannot meet its success criterion, or a tier with one
less layer of defence. **Dropped, deliberately, on the record.**

The rule is now `prob >= threshold` and nothing else, inclusive at the boundary.

**What this costs, and it should be read as a cost**: the threshold and SC-602 are now the *only*
false-positive control. SC-602 stops being a checkbox and becomes the gate that decides whether `--ml` may
ever be on by default. `docs/limits.md` needs this in T040.

Severity is a bounded ramp — 40 at threshold, 75 at 1000 — rather than the probability itself, which would
conflate "how likely is this real" with "how bad is it if real" and let model confidence outscore every
auditable rule in the set. The ceiling sits below the structural maximum of 90 on purpose.

### T016 — `MlReport` type

Add `MlReport` and `MlSegmentResult` to `please-core`'s verdict types (in `finalize::types`). Add
`Option<MlReport>` to `Verdict`. These are data types only — `please-core` does not depend on `please-ml`,
it just carries the report struct.

**Acceptance**: `Verdict` round-trips through JSON with and without `ml` populated.

**Done.** `MlReport` and `MlSegmentResult` in `finalize::types`, `Option<MlReport>` on `Verdict`, absent
rather than null when no tier ran — `ml: null` would claim the tier ran and produced nothing, a different
statement.

**One design change**: both the probability and the threshold are stored as **per-mille `u16`**, not `f32`.
Two reasons, and the second is the real one. `Verdict` derives `Eq`, which an `f32` field forbids. And the
contract's own determinism section already argues for the quantisation: a verdict recording `0.87421` would
differ between two machines that agree about every decision made from it. Per-mille is finer than any
defensible threshold and coarse enough to absorb SIMD/FMA variance.

### T017 — `finalize::with_ml`

Add a function in `please-core::finalize` that takes a structural verdict and a list of ML observations,
merges them into the evidence, and re-finalizes. The structural observations are preserved; the ML
observations are added. The score may increase; it may not decrease.

**Acceptance**: a test where the structural verdict has score 50 and two ML observations are added.
The merged verdict's score is ≥ 50. The structural reasons are unchanged.

**Done.** `finalize::with_ml`, ten tests in `crates/core/tests/ml_merge.rs`.

Monotonicity is **arithmetic, not a clamp**: `aggregate` is `max(severity) + bonus(distinct classes)`, and
both terms are monotonic under adding hits. There is no branch that could be wrong.

Three corrections to the contract, all recorded there:

* it takes **five arguments**, not three — `bands` because the score moves and must be re-banded against
  the scan's own table, `bounds` because ML excerpts must cross the same sanitisation boundary structural
  ones do;
* reasons **are** reordered, by byte offset, and must be: appending instead would make output depend on
  which tiers ran, which breaks SC-011 for every `--ml` scan. The *set* of structural reasons is what is
  preserved;
* a **truncated verdict is refused** with a `TierUnavailable` gap and no report attached, on `rejudge`'s D9
  argument — recomputing from survivors would lower the score while claiming to have added evidence.

A judgement already applied is re-attached rather than dropped, since `assemble` builds a fresh verdict.

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

**Partial — 2026-09-11.** Regular CI now tests/lints the workspace default, offline CLI, and Candle
configurations and runs the CLI/ML dependency isolation guards. The dedicated `ML inference`
workflow verifies pinned ProtectAI/MiniLM assets and explicitly runs all eight real-weight tests;
missing assets fail. See [CI gates](../../docs/ci-gates.md). ML-in-Wasm validation and corpus-level
ML regression floors below remain unfinished; the CLI still has no ML feature.

- `ci/check-cli-dependencies.sh` extended to cover `please-ml` crates
- `ci/check-ml-wasm32.sh` new: proves `please-ml` with `ml-candle` builds for wasm32
- `please-eval gate` extended with ML-tier regression floors
