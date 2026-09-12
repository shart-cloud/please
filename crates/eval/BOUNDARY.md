# Window-boundary evaluation

The `boundary` commands freeze exact input bytes with tokenizer-verified payload positions, then
measure the shipping `ScanSession`. Generation and checking require only the `boundary` feature;
real inference requires `shipping-ml`. They never download artifacts or invoke a remote judge.

A seed file is a JSON array of `{capture, group, split}` objects. `capture` uses the existing
[replay capture format](REPLAY.md), with input paths relative to the seed file and SHA-256 of the
exact payload bytes. `group` identifies a related family; `split` is `development` or `holdout`.
The same group or identical seed bytes cannot cross splits. Supply labels appropriate to the
payload embedded in ordinary padding. Generation inherits those labels; it cannot establish them.
The included `corpus/boundary/seeds.json` is authored development material, including matched
controls, UTF-8, a fenced payload, three input sources, and an over-window benign payload.
It is not an independent holdout or a deployment acceptance corpus.

```sh
cargo run --release --manifest-path crates/eval/Cargo.toml --features boundary -- \
  boundary generate --seeds crates/eval/corpus/boundary/seeds.json \
  --tokenizer /path/to/tokenizer.json --max-tokens 512 --out /tmp/boundary-suite

# Retain the printed digest separately. Check verifies both bytes and token geometry.
cargo run --release --manifest-path crates/eval/Cargo.toml --features boundary -- \
  boundary check --suite /tmp/boundary-suite/suite.json --sha256 PRINTED_DIGEST \
  --tokenizer /path/to/tokenizer.json

cargo run --release --manifest-path crates/eval/Cargo.toml --features shipping-ml -- \
  boundary run --suite /tmp/boundary-suite/suite.json --sha256 PRINTED_DIGEST \
  --ml-config /path/to/ml.json --split development --repeats 3 --out /tmp/boundary-zero
```

Generation places each payload at the first window, inside a window, immediately before a boundary,
across it, immediately after it, at the last window, and across a later boundary. For payloads longer
than half a window, the inside/before cases are omitted; the spanning cases remain. Padding joins
are re-tokenized to verify actual token positions. Unrealizable positions fail explicitly; a
one-token payload cannot straddle a token boundary. Output creation follows complete validation and
refuses an existing directory. Inputs are limited to 1 MiB, context sizes to 4–8192 tokens, suites to 4096 cases and repetitions to 100.

The v2 generator searches a bounded token-offset adjustment to an ordinary inventory-report prose
carrier. The carrier text is recorded in the suite. A discarded v1 pilot used repeated `word` tokens
and saturated the classifier on benign controls; those pilot outputs must not be pooled with v2. Its placement vocabulary is
relative to zero-overlap windows so **all overlap candidates receive identical bytes**. The run
rejects a tokenizer/context mismatch and re-verifies frozen zero-overlap geometry before inference.
`--split` defaults to development, keeping holdout inference explicit. Tokenizer-only verification
checks geometry in both splits without producing model outputs. Split declarations cannot prove
novelty or that an owner has never inspected a payload; use the existing capture freeze/exposure
workflow for a real holdout.

Shared ML configuration now accepts:

```json
{
  "model_path": "/path/to/model",
  "model_id": "my-classifier",
  "revision": "pinned-revision",
  "max_tokens": 512,
  "malicious_label": 1,
  "threshold": 700,
  "windowing": {
    "overlap_tokens": 0,
    "max_windows": 4096,
    "max_total_tokens": 2097152
  }
}
```

Omitted `windowing` or omitted fields use these defaults. Overlap counts payload tokens, excluding
special tokens; it must be smaller than payload capacity. Total work counts every model token,
including repeated overlap and special tokens. Invalid settings or exceeded work limits leave a
coverage gap in ordinary scans. The standalone experiment refuses an unavailable model before
creating a run; per-document inference failures remain in its reported denominators.

Each run writes `run.json`, `results.jsonl`, and `report.md`. Results contain all window scores and
spans, ML admission, product decision, gaps, realized placement, and per-repeat scan times. Policy is
fixed to enforcement and the shipping default impact/action threshold; provenance follows each
capture's source. Threshold and overlap come from the supplied shared ML configuration.
One model load and an explicit short warmup precede timed scans. Load time includes hashing and
construction against the host's current filesystem cache; it is not a cold-disk benchmark.
Peak RSS is the Linux process high-water mark (including the harness); other hosts record null.
Run latency comparisons with no competing builds/inference and preserve runtime metadata.

Reports separate ML recall/false positives from product blocks/reviews/allows. Inconclusive or
failed positive cases count as non-detections. Uncertain labels do not enter either binary class.
Counts are stratified by source, placement and byte length. Whole-group bootstrap intervals are
exploratory: small/degenerate groups cannot establish a population ceiling or the 1% target.
Use paired cases/groups when comparing overlaps; never count related placements as independent
samples. The current runner records the last repetition's verdict and every repetition's timing;
use single repetitions for accuracy runs and repeated runs for latency measurements.

Suggested development sweep: zero, 1/8, 1/4 and 1/2 of payload capacity, resolved to explicit integers.
Freeze a candidate and numeric accuracy/runtime criteria before running `--split holdout`.
No command automatically changes the shipping default or establishes a baseline. Without qualifying
holdout evidence and agreed runtime limits, zero overlap remains the default.
