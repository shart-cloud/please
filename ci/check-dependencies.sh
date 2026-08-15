#!/usr/bin/env bash
# Assert the default build's dependency set matches ci/dependency-allowlist.txt exactly.
#
# Constitution Principle V requires optional capability to be gated so that a build selecting none of it
# carries none of its dependencies, and requires that gating to be enforced by a check rather than by
# review.
#
# This is a shell script rather than a Rust test for a reason worth recording. The workspace root is not
# a package, so a `tests/` directory there is never compiled; and a test inside please-core cannot observe
# its own package's resolved default features, because dev-dependencies have already changed them. Only
# the build graph, viewed from outside, can answer the question.
#
# `--edges normal` excludes dev- and build-dependencies, which is what makes the question meaningful:
# proptest, criterion, and serde_json are test-only and must not count against the shipping graph.
set -euo pipefail

cd "$(dirname "$0")/.."

allowlist=ci/dependency-allowlist.txt
actual=$(mktemp)
allowed=$(mktemp)
trap 'rm -f "$actual" "$allowed"' EXIT

cargo tree -p please-core --edges normal --prefix none --no-dedupe \
  | sed 's/ v[0-9].*//' \
  | grep -v '^$' \
  | sort -u > "$actual"

grep -vE '^\s*#|^\s*$' "$allowlist" | sort -u > "$allowed"

unexpected=$(comm -23 "$actual" "$allowed")
stale=$(comm -13 "$actual" "$allowed")
status=0

if [ -n "$unexpected" ]; then
  status=1
  echo "error: the default build of please-core pulls dependencies that are not on the allow-list:" >&2
  echo "$unexpected" | sed 's/^/  + /' >&2
  echo >&2
  echo "A new dependency in the shipping graph is a design decision, not a chore. If it belongs there," >&2
  echo "add it to $allowlist with a comment saying why it is worth its weight." >&2
fi

if [ -n "$stale" ]; then
  status=1
  echo "error: $allowlist lists dependencies the build no longer pulls:" >&2
  echo "$stale" | sed 's/^/  - /' >&2
  echo >&2
  echo "The graph shrank, which is usually good news. Remove these lines and say so in the commit." >&2
fi

if [ "$status" -eq 0 ]; then
  echo "dependency allow-list: exact match ($(wc -l < "$actual" | tr -d ' ') crates)"
fi

exit "$status"
