#!/usr/bin/env bash
# Prove the preserved patch is self-contained on the committed original baseline.
set -euo pipefail
repo=$(git rev-parse --show-toplevel)
baseline=90f5676
checkout=$(mktemp -d "${TMPDIR:-/tmp}/please-role-patch.XXXXXX")
trap 'rm -rf -- "$checkout"' EXIT
git -C "$repo" archive "$baseline" | tar -x -C "$checkout"
test ! -e "$checkout/crates/core/tests/data/role_marker_controls.jsonl"
git -C "$checkout" apply --check "$repo/docs/research/role-marker-prefilter-candidate.patch"
git -C "$checkout" apply "$repo/docs/research/role-marker-prefilter-candidate.patch"
cmp "$checkout/rules/builtin.toml" "$repo/rules/builtin.toml"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$repo/target}"
cd "$checkout"
cargo test --locked --offline -p please-core --test role_marker_prefilter --test frame_matching
cmp crates/core/tests/data/role_marker_controls.jsonl "$repo/crates/core/tests/data/role_marker_controls.jsonl"
