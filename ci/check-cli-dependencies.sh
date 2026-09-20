#!/usr/bin/env bash
# Restore the HTTP/TLS and terminal dependency guard for the explicitly offline CLI configuration.
set -euo pipefail
cd "$(dirname "$0")/.."

actual=$(mktemp)
trap 'rm -f "$actual"' EXIT
cargo tree -p please-cli --no-default-features --locked --edges normal --prefix none \
  | sed 's/ v[0-9].*//' | sort -u > "$actual"
forbidden='^(please-judge|ureq|ureq-proto|reqwest|hyper|hyper-util|h2|rustls|rustls-.*|tokio-rustls|native-tls|openssl|openssl-sys|curl|curl-sys|ratatui|crossterm|ratatui-.*)$'
if grep -E "$forbidden" "$actual"; then
  echo "error: the offline CLI resolves an HTTP/TLS or TUI dependency" >&2
  exit 1
fi
echo "offline CLI dependency guard: no known HTTP/TLS or TUI stack"
