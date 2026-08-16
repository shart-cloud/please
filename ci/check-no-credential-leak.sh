#!/usr/bin/env bash
# SC-404 / FR-413: no credential value appears in any test output, asserted mechanically.
#
# "Asserted mechanically rather than by reading" is the requirement, and it is the right one: the natural
# way to write an error includes the thing that failed, and the body of a 401 can echo a token. A reviewer
# scanning for that catches it on the day they are looking for it.
#
# HOW THIS WORKS, and the detail that makes or breaks it:
#
#   `cargo test` CAPTURES stdout and prints it only for tests that FAIL. A green suite leaking a token on
#   every line would grep completely clean. `-- --nocapture` is therefore not a convenience here, it is the
#   whole check. quickstart.md originally specified this without it.
#
#   `--no-fail-fast` matters just as much, and for a reason specific to this repository. `cargo test` stops
#   after the first failing test BINARY, and the fixture accuracy tests are red at the 004 baseline by
#   design. Without this flag the run aborts before it ever reaches please-judge's tests — which are the
#   only ones that touch a credential. Found by mutation: leaking the value from `Debug` on purpose did not
#   fail this script, because the code that would have printed it never ran.
#
# Distinct canary values per variable, so a failure says WHICH credential leaked rather than only that one
# did. They are nonsense strings that cannot collide with anything a test legitimately prints.
set -euo pipefail

cd "$(dirname "$0")/.."

AUTH_CANARY='canary-auth-tok-3f8a1c9e2b7d4056'
OAUTH_CANARY='canary-oauth-tok-91b47e0da2c6f358'
KEY_CANARY='sk-ant-canary-api-key-6d2f80ab4917c3e5'

out=$(mktemp)
trap 'rm -f "$out"' EXIT

echo "running the suite with canary credentials in the environment..."

# `|| true` so a genuine test failure does not mask the leak check. A red suite and a leaking suite are
# different problems, and this script is only responsible for the second — it reports the first separately
# so nobody reads "no leak" as "all good".
set +e
ANTHROPIC_AUTH_TOKEN="$AUTH_CANARY" \
CLAUDE_CODE_OAUTH_TOKEN="$OAUTH_CANARY" \
ANTHROPIC_API_KEY="$KEY_CANARY" \
ANTHROPIC_BASE_URL="http://127.0.0.1:1" \
  cargo test --workspace --features please-cli/judge --no-fail-fast -- --nocapture > "$out" 2>&1
suite_status=$?
set -e

status=0
for pair in "ANTHROPIC_AUTH_TOKEN:$AUTH_CANARY" \
            "CLAUDE_CODE_OAUTH_TOKEN:$OAUTH_CANARY" \
            "ANTHROPIC_API_KEY:$KEY_CANARY"; do
  variable=${pair%%:*}
  canary=${pair#*:}
  hits=$(grep -c -- "$canary" "$out" || true)
  if [ "$hits" -ne 0 ]; then
    status=1
    echo "error: the value of $variable appeared in test output $hits time(s):" >&2
    grep -n -- "$canary" "$out" | head -5 | sed 's/^/  /' >&2
    echo >&2
    echo "FR-413: a judge failure must say WHICH VARIABLE was consulted, never what it contained." >&2
  fi
done

# A suite that did not COMPILE proves nothing about leaks, so that is fatal here. A suite that compiled,
# ran, and had failing tests is a different matter: this repository's fixture accuracy tests are RED at the
# 004 baseline by design (31/41 positives, one false positive — see docs/004-accuracy-baseline.txt), and
# those failures print more output rather than less. Treating them as fatal would make this check
# permanently unrunnable until an unrelated problem is solved, which is how a check gets deleted.
if grep -qE '^error: could not compile|^error\[E[0-9]+\]' "$out"; then
  echo "error: the suite did not compile, so it cannot demonstrate the absence of a leak." >&2
  grep -E '^error' "$out" | head -5 | sed 's/^/  /' >&2
  status=1
elif [ "$suite_status" -ne 0 ]; then
  echo "note: the suite exited $suite_status — some tests failed. Their output WAS scanned (failing tests"
  echo "      print more, not less), so the leak result above stands. Fix them separately."
fi

if [ "$status" -eq 0 ]; then
  echo "credential leak check: no canary value in any test output ($(wc -l < "$out" | tr -d ' ') lines scanned)"
fi

exit "$status"
