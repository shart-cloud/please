#!/usr/bin/env bash
# Assert please-core touches no network, no filesystem, no clock, and no subprocess (FR-031, D10, D15).
#
# The dependency allow-list cannot prove this. Reaching the network in Rust needs no dependency at all —
# `std::net` is in the standard library — so an allow-list covers a *dependency* opening a socket and is
# blind to the engine's own code doing it. This closes that half.
#
# Why each is forbidden:
#
#   std::net       A network call in a security path is a fail-open waiting to happen: the scanner would
#                  start returning inconclusive, or worse clean, whenever a service was slow.
#   std::fs        Reading a target is the caller's job. The core takes bytes. This is also what lets the
#                  same engine run in a browser.
#   std::process   A detector that spawns a subprocess is an execution surface, in a tool whose entire
#                  purpose is to sit in front of one.
#   std::time      Instant does not work on wasm32-unknown-unknown, and a timed bound is
#                  non-deterministic, which byte-identical output cannot afford. Bounds are counted.
#
# `tests/` and `benches/` are exempt: measuring elapsed time is exactly what a benchmark is for.
set -euo pipefail

cd "$(dirname "$0")/.."

forbidden=(
  'std::net'
  'std::fs'
  'std::process'
  'std::time'
)

# Comment lines are excluded, because the documentation explaining why these are forbidden naturally
# mentions them — the first run of this script flagged its own rationale. Matching `//`, `///`, `//!`, and
# `*` continuation lines covers doc comments and block-comment bodies. It would miss a call hidden on the
# same line as a trailing comment, which is a limitation worth knowing rather than pretending away: the
# check is a guard against drift, not a proof, and the wasm32 build is the independent corroboration.
status=0
for path in "${forbidden[@]}"; do
  # -F for a literal match; the pattern contains `::` and no regex is wanted here. The second grep drops
  # comment lines, anchoring after grep -n's own `file:line:` prefix.
  hits=$(grep -rnF "$path" crates/core/src --include='*.rs' 2>/dev/null \
    | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*)' || true)
  if [ -n "$hits" ]; then
    status=1
    echo "error: please-core must not use \`$path\`:" >&2
    echo "$hits" | sed 's/^/  /' >&2
  fi
done

if [ "$status" -ne 0 ]; then
  echo >&2
  echo "See the header of $0 for why each of these is forbidden. If one is genuinely needed, that is a" >&2
  echo "constitution question (Principle V), not a lint to silence." >&2
  exit "$status"
fi

echo "core isolation: no network, filesystem, subprocess, or clock use in crates/core/src"
