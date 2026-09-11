# Caller-controlled source policies

The lab chooses a source from its own routing and intended use. The scanned text cannot select it.
A code fence in a security lesson and a code fence in an untrusted tool response have different
operational meanings, even when they contain exactly the same instruction.

## Policy contract

| Source | Quote suppression | Intended use |
| --- | --- | --- |
| `unspecified` | On by default; caller can disable | Compatibility with existing callers |
| `security_reference` | On by default; caller can disable | Material the caller selected as a lesson, advisory, or reference for analysis |
| `untrusted_tool_response` | Always off | Lower-trust tool output, including MCP tool responses |
| `untrusted_user_input` | Always off | Untrusted user task requests subject to application instructions |

All four start at the shipped `High` threshold and enable all eight classes. They use the same
bounds: 1 MiB input, decode depth 3, 16 matches per rule, 64 reasons, and 256-byte excerpts.
The caller can change the threshold, class selection, and limits. The untrusted-source policies override
`suppress_in_quotes = true` so a direct struct update cannot accidentally restore quote suppression.
`--no-suppress-in-quotes` also works with security references.

`security_reference` is not a declaration that all content is safe: an unquoted instruction still
fires, and concealment and other detections that already fire in quotes retain their behavior.
Do not promote a tool response to security reference because it calls itself a lesson, includes
frontmatter, has a `.md` filename, or asks the scanner to change policy. If a reference is deliberately
retrieved through a tool, the application must establish that intended use independently of the response.

## Try the paired examples

From the repository root, after building the CLI:

```bash
cargo build -p please-cli --offline --locked
./target/debug/plz scan --format json --source security-reference tests/fixtures/source-policy/security-lesson.md
# exit 0: quoted findings retained in suppressed
./target/debug/plz scan --format json --source untrusted-tool-response tests/fixtures/source-policy/tool-response.md
# exit 1: the same instruction is active and reaches High
```

You can also scan the *same file* twice with different `--source` values. Source context is independent
of its bytes. `--source` applies to every target in an invocation; use separate invocations for mixed
sources. Omitting it preserves historical detection behavior.

In Rust, reuse the engine and choose the policy at the integration boundary:

```rust
use please_core::{Engine, ScanPolicy, ScanSource, TargetRef};

let engine = Engine::builtin()?;
let tool_policy = ScanPolicy::for_source(ScanSource::UntrustedToolResponse);
let bytes = b"tool result supplied by the lab";
let verdict = engine.scan(bytes, &tool_policy, TargetRef::buffer("search-result", bytes.len()));
```

The scanner reports evidence. The lab still owns blocking: block findings at or above its threshold,
handle incomplete coverage explicitly, and decide what to do with below-threshold findings. Checking
only `score` can mistake an inconclusive zero-score result for a clean result. The score is a heuristic,
not a calibrated probability.

## Attribution and optional tiers

`Verdict::scan_policy()` records the effective structural policy, including source, threshold,
suppression, classes, and limits. JSON emits this as `scan_policy`, even for an input-size refusal.
ML merges, judgment, and subsequent failures retain it. Standalone finalization and I/O-only
failures have no scan policy snapshot. Human CLI output names an explicitly selected source,
threshold, and suppression setting for clean, risky, and inconclusive scans.

The judge receives caller source context outside the document envelope. Tool-response candidates
remain active through structural scanning and can therefore reach the judge. A security reference
with only suppressed findings still skips judgment. Judgment can demote active findings; its decisions
under the new context have not been measured with a live provider. This milestone's acceptance
results cover structural scanning, not the accuracy of combined structural/ML/judge decisions.
The request version is `2026-09-10.3`.

API compatibility: `ScanPolicy` has a new `source` field; exhaustive struct literals need to supply it
or use `..ScanPolicy::default()`. Existing `Engine::scan` calls continue to work. JSON has a new optional
`scan_policy` field in the published schema; consumers using an older strict schema must update it.

## Paired acceptance evidence — 2026-09-10

The fixture manifest is `tests/fixtures/source-policy/cases.json`. Each row is scanned under both
sources with byte-identical input, using engine `please-core` 0.1.0 and ruleset `please.builtin` 0.1.0,
digest `3b946803b23151d5`. No model participates. These are hand-authored regression cases, not
population accuracy estimates or a deployment acceptance claim.

| Input | Security reference | Untrusted tool response |
| --- | --- | --- |
| Fenced lesson example | Clean; candidate suppressed | RiskFound, score 90, above High |
| Inline-code example | Clean; candidate suppressed | RiskFound, score 90, above High |
| Blockquote example | Clean; candidate suppressed | RiskFound, score 90, above High |
| Quoted-string example | Clean; candidate suppressed | RiskFound, score 90, above High |
| Ordinary runbook imperative | Clean | Clean |
| Ordinary fenced test result | Clean | Clean |
| Unquoted suspicious instruction | RiskFound, score 90 | RiskFound, score 90 |

All 14 outcomes match expectations; none records incomplete coverage. Other regressions check
source-spoofing text, retained candidate identity, reuse of one engine across policy changes,
explicit suppression overrides, size refusals, attribution through later tiers, judge request
eligibility, CLI exit status, and JSON schema conformance.

Reproduce the matrix without network access:

```bash
cargo test -p please-core --test source_policy --offline --locked -- --nocapture
```

Validation for this milestone: the offline workspace run completed with 522 passed, two known legacy
fixture failures, and 11 ignored tests. CLI tests with `--no-default-features`, the core
`wasm32-unknown-unknown` build, and workspace Clippy with warnings denied all passed. No external
model calls or deployment changes were made.

Next lab evidence should include real response envelopes and task roles, legitimate security content
returned by tools as a hard negative, repository instructions, broader hostile/benign pairs, and an
identical-input comparison with the existing scanner. Cold/warm latency, memory, Worker runtime
behavior, and combined-tier accuracy remain unmeasured here. The two existing legacy fixture gates
remain failing and their known-miss evidence is unchanged.

## Actual user-input replay

The [SHART replay](research/lab-replay-shart-2026-09-10.md) adds an accurately attributed
`untrusted_user_input` source for the lab's `UserMessage` boundary and measures 20 real inputs.
Please blocked 1 of 14 labeled injections versus 7 of 14 for the existing input scanner; neither
blocked the five ordinary benign controls. This is separate from the synthetic paired evidence
above and exposes gaps that quote suppression and threshold changes would not resolve.
