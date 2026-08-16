#!/usr/bin/env bash
# Assert the gating of the judgement tier, in three directions.
#
# Constitution Principle V requires optional capability to be gated so that a build selecting none of it
# carries none of its dependencies, AND requires that gating be enforced by a check rather than by review.
# `ci/check-dependencies.sh` discharges that for `please-core`. It has never covered `please-cli`, which was
# fine while the CLI had no optional capability — feature 004 gives it one, and this script is the gap
# (plan.md Constitution Check, FR-419, SC-405).
#
# THREE ASSERTIONS, not one, and the third is the one people forget:
#
#   1. EXACT MATCH   the default `please-cli` graph equals ci/cli-dependency-allowlist.txt.
#                    Same technique and same reasoning as check-dependencies.sh: an exact match catches a
#                    crate arriving under a name nobody thought to look for.
#
#   2. ABSENCE       no HTTP or TLS crate in the default graph, by name.
#                    Redundant against (1) by construction, and kept anyway because it names the failure.
#                    "+ ureq" in a diff of fifty lines is a puzzle; "the default build of plz now links an
#                    HTTP client" is a sentence.
#
#   3. PRESENCE      `--features judge` DOES pull them.
#                    A gate that only ever checks for absence passes trivially when the feature is broken,
#                    misspelled, or silently dropped from Cargo.toml — and then reports success while the
#                    capability it guards does not exist. Absence is only meaningful as half of a pair.
#
# `--edges normal` excludes dev- and build-dependencies, which is what makes the question meaningful:
# proptest, criterion and trybuild are test-only and must not count against the shipping graph.
set -euo pipefail

cd "$(dirname "$0")/.."

allowlist=ci/cli-dependency-allowlist.txt
actual=$(mktemp)
allowed=$(mktemp)
judged=$(mktemp)
trap 'rm -f "$actual" "$allowed" "$judged"' EXIT

# Crates that must never appear in a build of `plz` that did not ask for the judgement tier. Matched as
# whole names, so `regex-automata` cannot be mistaken for a TLS crate and `ring` cannot match `stringprep`.
forbidden='^(ureq|ureq-proto|rustls|rustls-pki-types|rustls-webpki|webpki|webpki-roots|ring|aws-lc-rs|aws-lc-sys|hyper|h2|tokio|reqwest|native-tls|openssl|openssl-sys)$'

graph_of() {
  cargo tree -p please-cli --edges normal --prefix none --no-dedupe "$@" \
    | sed 's/ v[0-9].*//' \
    | grep -v '^$' \
    | sort -u
}

graph_of > "$actual"
grep -vE '^\s*#|^\s*$' "$allowlist" | sort -u > "$allowed"

status=0

# ── 1. Exact match ──────────────────────────────────────────────────────────────────────────────
unexpected=$(comm -23 "$actual" "$allowed")
stale=$(comm -13 "$actual" "$allowed")

if [ -n "$unexpected" ]; then
  status=1
  echo "error: the default build of please-cli pulls dependencies that are not on the allow-list:" >&2
  echo "$unexpected" | sed 's/^/  + /' >&2
  echo >&2
  echo "The default \`plz\` binary is the one users install. A new dependency in it is a design decision," >&2
  echo "not a chore. If it belongs there, add it to $allowlist with a comment saying why." >&2
  echo "If it arrived from the judgement tier, the \`judge\` feature is not gating what it claims to." >&2
fi

if [ -n "$stale" ]; then
  status=1
  echo "error: $allowlist lists dependencies the default build no longer pulls:" >&2
  echo "$stale" | sed 's/^/  - /' >&2
  echo >&2
  echo "The graph shrank, which is usually good news. Remove these lines and say so in the commit." >&2
fi

# ── 2. Absence, by name ─────────────────────────────────────────────────────────────────────────
network=$(grep -E "$forbidden" "$actual" || true)
if [ -n "$network" ]; then
  status=1
  echo "error: the DEFAULT build of \`plz\` links an HTTP or TLS crate:" >&2
  echo "$network" | sed 's/^/  ! /' >&2
  echo >&2
  echo "Principle V: a build selecting none of the optional capability must carry none of its" >&2
  echo "dependencies. The central promise of this tool is that it needs no network; a default build that" >&2
  echo "can open a socket breaks that promise whether or not it ever does." >&2
fi

# ── 3. Presence under the feature ───────────────────────────────────────────────────────────────
#
# Skipped when the feature does not exist yet — this script is written at T003, deliberately BEFORE the
# dependency it guards lands at T004, and a gate that fails for the whole of Phase 1 gets disabled.
if cargo tree -p please-cli --edges normal --features judge >/dev/null 2>&1; then
  graph_of --features judge > "$judged"
  present=$(grep -E "$forbidden" "$judged" || true)
  if [ -z "$present" ]; then
    status=1
    echo "error: \`--features judge\` pulls no HTTP or TLS crate." >&2
    echo >&2
    echo "The tier cannot reach an endpoint without one, so either the feature is misspelled, the" >&2
    echo "optional dependency is not wired to it, or please-judge lost its client. Absence in the" >&2
    echo "default build is only evidence of gating if the feature build differs — otherwise this" >&2
    echo "script passes by checking nothing." >&2
  fi
else
  echo "note: the \`judge\` feature does not exist yet; skipping the presence check (T003 precedes T004)"
fi

if [ "$status" -eq 0 ]; then
  echo "cli dependency allow-list: exact match ($(wc -l < "$actual" | tr -d ' ') crates), no HTTP or TLS crate"
fi

exit "$status"
