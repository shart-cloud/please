# Prompt-injection bench quickstart

Run these commands from the repository root on Linux or Ubuntu under WSL.

## Verify the committed development pilot

```bash
cargo run --manifest-path crates/eval/Cargo.toml -- \
  bench pack check \
  --pack crates/eval/corpus/bench/contextual-pilot/pack.json

cargo run --manifest-path crates/eval/Cargo.toml -- \
  bench experiment \
  --manifest crates/eval/bench/contextual-pilot.experiment.json
```

This validates 30 groups and 120 cases without invoking either system.

## Run and report

Choose a new output path; the runner refuses an existing directory.

```bash
cargo run --manifest-path crates/eval/Cargo.toml -- \
  bench run \
  --experiment crates/eval/bench/contextual-pilot.experiment.json \
  --out /tmp/please-bench-pilot

cargo run --manifest-path crates/eval/Cargo.toml -- \
  bench report \
  --run /tmp/please-bench-pilot \
  --out /tmp/please-bench-pilot-report.md
```

The example compares the frozen PLEASE structural mechanism with a deterministic context-aware process
fixture. The fixture proves the instrument and is not a research baseline or deployment-accuracy claim.

## Check deterministic replay

Run the unchanged experiment into another new directory, then compare:

```bash
cargo run --manifest-path crates/eval/Cargo.toml -- \
  bench compare \
  --left /tmp/please-bench-pilot \
  --right /tmp/please-bench-pilot-replay
```

Comparison rejects different pack, system, normalizer, or operating-point identities.

## Record exposure

After a development or holdout run influences a decision, record every case before preparing another
holdout:

```bash
cargo run --manifest-path crates/eval/Cargo.toml -- \
  bench exposure \
  --run /tmp/please-bench-pilot \
  --out /tmp/contextual-pilot-exposure.jsonl \
  --use-kind development_reporting \
  --recorded-at 2026-09-12T00:00:00Z
```

Exposure output is new-file-only and contains identities, not prompt text.

## Authoring and adding systems

Set a new pack's `content_digest` to any 64 lowercase hex characters, run `bench pack digest --pack ...`,
replace the placeholder with the printed digest, then run `bench pack check`. For an external adapter, copy
the strict system schema, bind `program` to an exact executable SHA-256, declare network capability, provide
one normalizer for every supported surface, and verify it with `bench system --manifest ...`.

Protocol and interpretation details are in `crates/eval/BENCH.md`. Real models, remote reviewers, gated
datasets, and third-party research tools remain explicit manual evaluations.
