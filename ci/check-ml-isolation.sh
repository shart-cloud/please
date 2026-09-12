#!/usr/bin/env bash
# Assert the default `plz` build reaches none of the ML tier (006 T010).
#
# Constitution Principle V requires optional capability to be gated so a build selecting none of it
# carries none of its weight, and requires the gating to be enforced by a check rather than by review.
# ci/check-dependencies.sh already makes that guarantee for please-core, and makes it *by construction*:
# it runs `cargo tree -p please-core`, and a crate that depends on core cannot appear in core's own tree.
#
# The CLI has no such structural protection. It is the crate that will grow a `--ml` flag in Phase 2, and
# the natural way to write that flag is a plain dependency — which would put Candle's 112 crates and
# 6.5 MiB (T001, measured) into every `cargo install plz`, for a tier that is opt-in at the prompt and
# whose weights most users will never download.
#
# So this guard exists BEFORE the edge does. That ordering is the point: a guard added after the mistake
# is a guard that has to argue for reverting something, and a guard added before it is a guard that has
# to be deliberately worked around.
#
# What is permitted: an OPTIONAL dependency behind a non-default `ml` feature, exactly as `judge` was
# introduced. What is not: anything that resolves in the default feature set.
set -euo pipefail

cd "$(dirname "$0")/.."

# The ML tier itself, plus the two heaviest things it brings and the one that surprises people —
# `tokenizers` pulls `rayon`, so a crate that swore off a thread pool acquires one transitively.
forbidden='^(please-ml|candle-core|candle-nn|candle-transformers|candle-onnx|tokenizers|ug|gemm)$'

actual=$(mktemp)
trap 'rm -f "$actual"' EXIT

cargo tree -p please-cli --edges normal --prefix none --no-dedupe \
  | sed 's/ v[0-9].*//' \
  | grep -v '^$' \
  | sort -u > "$actual"

found=$(grep -E "$forbidden" "$actual" || true)

if [ -n "$found" ]; then
  echo "error: the DEFAULT build of please-cli reaches the ML tier:" >&2
  echo "$found" | sed 's/^/  + /' >&2
  echo >&2
  echo "The ML tier is opt-in at the prompt (--ml) and its weights are a separate download of up to" >&2
  echo "1.08 GiB. A default build that links it charges every user for a tier most will never run." >&2
  echo >&2
  echo "Make the dependency optional and put it behind a non-default 'ml' feature, the way 004" >&2
  echo "introduced the judgement tier. See crates/ml/Cargo.toml for the full argument." >&2
  exit 1
fi

echo "ml isolation: the default plz build reaches no inference backend"
