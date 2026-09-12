# ML tier: current commands

**Feature**: `006-local-ml-tier` — September 11, 2026

The CLI supports an opt-in local classifier through `ml-candle`. Default builds carry no ML
backend. Build a local-inference CLI (omit `--no-default-features` if you also need `--judge`):

```bash
cargo build --release -p please-cli --no-default-features --features ml-candle --locked
```

## Configure and scan

Create a local JSON configuration with your actual model directory. Relative model paths resolve
against this file. All fields are required. The threshold is explicit, in per-mille: 700 below is
an example from existing instrument checks, not a calibrated production recommendation.

```json
{
  "model_path": "/absolute/path/to/protectai-deberta-v3-small/d7c8842daf06de3179cc3aca76b7b3a057acc5e7",
  "model_id": "protectai-deberta-v3-small",
  "revision": "d7c8842daf06de3179cc3aca76b7b3a057acc5e7",
  "max_tokens": 512,
  "malicious_label": 1,
  "threshold": 700
}
```

The directory must hold `config.json`, `tokenizer.json`, and `model.safetensors` for a supported
DeBERTa-v2/v3 sequence classifier. Scanning never downloads a model. Acquisition remains the eval
tool's explicit `model fetch` command; its `model check` command verifies cached assets against
[the pinned manifest](../../crates/eval/corpus/models.toml).

```bash
target/release/plz scan --ml --ml-config /path/to/ml.json --format json skill.md
target/release/plz scan --ml --ml-config /path/to/ml.json --explain skill.md
target/release/plz scan --ml --no-ml skill.md
```

The last ML toggle wins. Disabled ML does not read configuration or weights and reproduces the
structural verdict. Invalid/missing configuration is a usage error (64); unavailable weights or
failed inference add `tier_unavailable`. Clean input then exits 2, while existing risk stays reported
under the ordinary exit-code contract. One loaded model serves all targets in an invocation.

The library's `please_ml::scan` classifies the complete original document, including documents with
no structural findings. Long inputs use the existing model chunker and maximum-score pooling.
ML evidence is composed through core's finalizer before optional judge review. It does not require
structural or embedding corroboration; see [the measured contract decision](contracts/ml-tier.md).

JSON contains the existing `ml` report: model identity, revision, weights digest, threshold, and
one document-wide probability/span. Human output includes that attribution, even for clean results.
The span is not a localization of the highest-scoring model chunk. Source/quotation semantics and
export permissions govern structural detection; they are not model inputs or ML suppressors.

Model findings require the `agent_directed` class. Disabling it while requesting ML reports an
unavailable tier. Oversized inputs and truncated structural evidence are not classified. Complete
inference can be slow on long inputs; long finding excerpts retain the ordinary truncation gap.
Model IDs/revisions are caller claims. The weights digest is measured, but config/tokenizer pin
verification remains the separate `model check` step. Avoid modifying model assets during scanning.

## Verify offline

With dependencies and pinned assets already cached:

```bash
cargo test -p please-ml --offline --locked
cargo test -p please-cli --no-default-features --features ml-candle --offline --locked
bash ci/check-ml-inference.sh
```

The first two commands exercise logic and CLI contracts without running real inference. The last
verifies all pinned ProtectAI and MiniLM asset sizes/hashes, then runs eight ignored library tests
and the ignored CLI classifier integration test. Missing assets fail. `PLEASE_EVAL_CACHE` selects
the cache root; otherwise it uses `$XDG_CACHE_HOME/please-eval` or `~/.cache/please-eval`.
See [CI gates](../../docs/ci-gates.md). Run local feature configurations sequentially when sharing
`target/`, because integration tests execute the same `plz` binary path.

## Remaining scope

There is no ONNX backend, embedding CLI, selective-inference CLI, `plz ml fetch/list`, or ML corpus
comparison command. The older planned flags (`--ml-classify`, `--ml-embed`, `--ml-full`,
`--ml-threshold`, `--model-path`, `--ml-model`) are not implemented; configuration belongs in
`--ml-config` for this milestone. Embedding scores remain an experimental library diagnostic.

The integration tests establish usable local inference, not corpus accuracy or release readiness.
ML remains opt-in pending independent evaluation and a measured per-model threshold. Use
[the fresh capture workflow](../../crates/eval/CAPTURE.md) before further detector tuning.
