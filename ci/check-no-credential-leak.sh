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
# Run every test target even when one fails, so a failure cannot hide later credential output.
# Test failures are fatal after the output has also been checked for leaks.
#
# Distinct canary values per variable, so a failure says WHICH credential leaked rather than only that one
# did. They are nonsense strings that cannot collide with anything a test legitimately prints.
set -euo pipefail

cd "$(dirname "$0")/.."

AUTH_CANARY='canary-auth-tok-3f8a1c9e2b7d4056'
OAUTH_CANARY='canary-oauth-tok-91b47e0da2c6f358'
KEY_CANARY='sk-ant-canary-api-key-6d2f80ab4917c3e5'
TYPESAFE_CANARY='canary-typesafe-api-key-283afc7091ed654b'

out=$(mktemp)
trap 'rm -f "$out"' EXIT

echo "running the suite with canary credentials in the environment..."

# Retain the exit status while checking all captured output for credential leaks.
set +e
ANTHROPIC_AUTH_TOKEN="$AUTH_CANARY" \
CLAUDE_CODE_OAUTH_TOKEN="$OAUTH_CANARY" \
ANTHROPIC_API_KEY="$KEY_CANARY" \
TYPESAFE_API_KEY="$TYPESAFE_CANARY" \
ANTHROPIC_BASE_URL="http://127.0.0.1:1" \
  cargo test --workspace --locked --no-fail-fast -- --nocapture > "$out" 2>&1
suite_status=$?
set -e

status=0
for pair in "ANTHROPIC_AUTH_TOKEN:$AUTH_CANARY" \
            "CLAUDE_CODE_OAUTH_TOKEN:$OAUTH_CANARY" \
            "ANTHROPIC_API_KEY:$KEY_CANARY" \
            "TYPESAFE_API_KEY:$TYPESAFE_CANARY"; do
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

if [ "$suite_status" -ne 0 ]; then
  echo "error: the test suite exited $suite_status; output was checked for leaks, but the gate failed." >&2
  tail -30 "$out" >&2
  status=1
fi

if [ "$status" -eq 0 ]; then
  echo "credential leak check: no canary value in any test output ($(wc -l < "$out" | tr -d ' ') lines scanned)"
fi

exit "$status"
