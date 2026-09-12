# Caller-owned profiles, provenance, and context

Scan purpose and input origin are separate. The scanned document cannot select either.

| Profile | Quote suppression | Use |
| --- | --- | --- |
| `enforcement` (default) | Always off | Checking content before an agent consumes it |
| `reference_analysis` | On unless the caller disables it | Explicitly analyzing quoted examples as reference material |

`InputProvenance` independently records `unspecified`, `caller_provided`, `user_input`, or
`tool_response`. Reference analysis is a caller choice, including when the reference arrived through
a tool; it does not promote that tool's authority. Review remains advisory unless release is
explicitly authorized.

```sh
plz scan --profile enforcement --provenance tool-response response.txt
plz scan --profile reference-analysis --provenance caller-provided lesson.md
```

```rust
use please_core::{InputProvenance, ScanPolicy};
let policy = ScanPolicy {
    provenance: InputProvenance::ToolResponse,
    ..ScanPolicy::default()
};
let session = please_scan::ScanSession::new(&engine, policy);
let verdict = session.scan(bytes, target);
```

The default threshold is High. Input, matching, decoding, retained observation, and display budgets
remain independent. `suppress_in_quotes=true` cannot override enforcement. JSON and human output
record the effective profile and provenance.

`ScanSource` / `--source` remain compatibility adapters: a security reference explicitly selects
reference analysis; user/tool input selects enforcement. Omitting source no longer preserves the
old quote-suppressing default. New callers should select profile and provenance separately.

Bind host-owned task and permission context with `ScanPolicy::caller_context` before scanning, or
use `--judge --review-context PATH` with established provenance. Reports expose only its identity;
the requested judge receives the context text. Content under analysis cannot grant permissions.
The detailed [migration and pipeline notes](research/policy-and-pipeline-2026-09-11.md) explain the
API, output changes, independent ML impact policy, and shared evaluation path.

The following acceptance evidence describes the earlier compatibility source configuration, not a
new measurement of default enforcement or any optional model tier.

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
