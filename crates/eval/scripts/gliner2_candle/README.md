# GLiNER2 classification in Candle

This experiment runs **PLEASE's native test bench** with a Rust/Candle subprocess adapter.
The adapter implements single-label GLiNER2 classification: schema compilation, the official
word splitter and tokenizer behavior, DeBERTa-v2, the two-layer classification head, and softmax.
It does not implement GLiNER2 entity/relation extraction or change the shipping scanner.

Model: `fastino/gliner2-base-v1`, revision `79c3a777abc572b4767922f3916cf63fb5754df2`.
Reference: `gliner2==2.0.0`; the library and model versions are distinct.
Runtime: Candle 0.11, CPU, f32, four Rayon threads per adapter. No Python or network calls during
benchmark inference. Model assets and schema recipes are hash-checked on startup. Inputs over
512 encoded tokens (including schema) abstain without truncation; reserved tokenizer markers
also abstain. The 0.7 top-probability threshold is exploratory and uncalibrated.

## Validation before a benchmark

`reference.py` uses the official Python model **only as an offline parity oracle**. It writes
18 first-party synthetic probes (including two exact 512-token inputs) and 128 seeded Unicode/
punctuation tokenization probes. `check_parity.py` requires identical token IDs, schema label
positions, top labels and threshold decisions, with maximum absolute error <=0.001 for logits
and <=0.0001 for probabilities. These are implementation checks, not accuracy evidence.

The committed `tests/fixtures/gliner2-candle-parity.json` contains only synthetic inputs and
reference outputs. Tokenization fixtures and reserved-marker guards can be rechecked with:

```bash
GLINER2_MODEL_DIR=/path/to/pinned/model cargo test \
  --manifest-path crates/eval/Cargo.toml --release --features ml \
  gliner2::tests --lib -- --include-ignored
```

Build and run the score parity probe:

```bash
cargo build --manifest-path crates/eval/Cargo.toml --release --features ml,jev --bins
RAYON_NUM_THREADS=4 crates/eval/target/release/please-eval-gliner2 \
  --model-dir /path/to/pinned/model < parity.probes.jsonl > parity.candle.final.jsonl
python3 crates/eval/scripts/gliner2_candle/check_parity.py \
  parity.reference.jsonl parity.candle.final.jsonl --out parity.result.json
```

`prepare.py` verifies completed parity outputs before freezing the adapter, runner, recipes,
model lock, and native system/experiment manifests. It copies the previously selected Jev public
and contextual packs without selecting rows based on GLiNER2 results. Existing freezes are never
replaced. The cache's original Python reference recipe is converted to ordered Rust labels, so
JSON map ordering cannot silently change the schema.

## Run through PLEASE

The September 18 frozen experiments live in `.cache/framework-models-20260918/`:

```bash
.cache/framework-models-20260918/please-eval bench run \
  --experiment .cache/framework-models-20260918/public.experiment.json \
  --out .cache/framework-models-20260918/run-public
.cache/framework-models-20260918/please-eval bench run \
  --experiment .cache/framework-models-20260918/contextual.experiment.json \
  --out .cache/framework-models-20260918/run-contextual
```

Each run creates the native `run.json`, `results.jsonl`, and offline `report.html`. Once complete:

```bash
.cache/framework-models-20260918/please-eval bench view \
  --run .cache/framework-models-20260918/run-public
```

A run directory is immutable; choose a fresh output path to repeat a run. The native framework
verifies saved results before opening them. Corpus text and weights stay in ignored cache.
The public pack contains 6,000 rows, while the 600 contextual rows reuse 50 distinct candidate
texts in correlated caller-context/delivery variants. Neither is a release-quality holdout.

The active September 18 runs have a bounded completion watcher. It waits for both native runs,
checks saved-run integrity and frozen inputs, and publishes the comparison to
`docs/research/framework-model-comparison-2026-09-18.{md,json}`. Status is recorded in
`.cache/framework-models-20260918/completion.json` and progress in `completion.log`.
A failed verification is recorded as failed, with no automatic rerun or additional API calls.
The comparison also retains per-language, harmful-label, input-length and contextual strata.
