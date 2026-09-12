#!/usr/bin/env bash
# Explicit real-inference gate. No downloads; all pinned runtime assets must already exist.
set -euo pipefail
cd "$(dirname "$0")/.."

export HF_HUB_OFFLINE=1
export TRANSFORMERS_OFFLINE=1
cargo run --manifest-path crates/eval/Cargo.toml --offline --locked -- \
  model check protectai-deberta-v3-small all-minilm-l6-v2
cargo test --release -p please-ml --features candle --test real_weights --offline --locked -- \
  --ignored --nocapture --test-threads=1
cargo test --release -p please-cli --no-default-features --features ml-candle \
  --test ml_cli --offline --locked -- --ignored --nocapture --test-threads=1
