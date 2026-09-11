# Replay captured lab inputs

`please-eval replay` scans local captured bytes with Please and compares them with saved results from
an existing scanner. It makes no external requests, invokes no baseline scanner, and does not tune
rules or thresholds. A first actual lab comparison is documented in
[`docs/research/lab-replay-shart-2026-09-10.md`](../../docs/research/lab-replay-shart-2026-09-10.md).

The current Please path uses the structural engine with the caller-selected source at the shipped
`High` threshold. It reuses one engine for the entire set. Its results include the full effective
policy, rule/engine identity, findings, suppressed candidates, and incomplete coverage. The baseline
keeps its own reported decision, reasons, version, and configuration; scores from different scanners
are not treated as comparable probabilities.

## Choose a small labeled set

Start with roughly 10–20 actual inputs at the boundary where the lab calls its scanner: both expected
hostile inputs and legitimate controls, including security lessons and ordinary tool responses.
Preserve the bytes and the envelope the scanner actually sees, including newlines. Do not replace
captured content with a paraphrase. A modified/redacted capture is a new input and must be run through
both scanners again.

Label each capture `benign`, `injection`, or `uncertain`, with a short rationale based on the lab's
actual task. Keep labels separate from scanner inputs. Record the caller-owned `source` and
`control_role`; do not derive them from a payload's claim to be trusted. Uncertain labels remain in
the disagreement report but are excluded from label-error counts.

Keep captures and results in a local directory such as `/tmp/lab-replay/` or the ignored `.cache/`.
The repository does not contain a committed set of actual lab captures or baseline results.
The first measured SHART run keeps its real captures and outputs under the ignored
`.cache/lab-replay/shart-ai-20260910/` directory.
The following JSON is a format illustration, not a captured example or measured scanner output.

## Capture manifest

One object per line in `captures.jsonl`:

```json
{"id":"lab-tool-01","input_path":"inputs/lab-tool-01.bin","input_sha256":"REPLACE_WITH_LOWERCASE_SHA256","source":"untrusted_tool_response","control_role":"tool","label":"injection","label_reason":"The returned text asks the agent to act outside the lab task."}
```

`input_path` is relative to the manifest's directory. Absolute paths also work. The file can contain
arbitrary bytes; UTF-8 decoding or newline normalization is not performed before hashing or scanning.
Calculate its hash with `sha256sum /tmp/lab-replay/inputs/lab-tool-01.bin`.

Supported sources are `security_reference`, `untrusted_tool_response`, and `untrusted_user_input`. A replay requires an explicit
choice rather than silently using `unspecified`. `control_role` records the baseline scanner's caller
role, for example `tool`; preserve the actual value used by the integration. Different roles or
source policies for the same bytes require separate capture IDs.

## Existing-scanner export

Run the existing scanner on those exact bytes and caller roles using its current configuration.
Export one normalized row per capture to `baseline.jsonl`:

```json
{"id":"lab-tool-01","input_sha256":"REPLACE_WITH_LOWERCASE_SHA256","source":"untrusted_tool_response","control_role":"tool","scanner":{"name":"EXISTING_SCANNER_NAME","version":"EXACT_VERSION_OR_COMMIT","configuration":{"threshold":"ACTUAL_THRESHOLD","role_mapping":"ACTUAL_MAPPING"}},"decision":"block","reasons":["The existing scanner's actual reason or rule identifier"],"incomplete":false,"error":null}
```

This normalized export is the adapter boundary. The export must come from the identified baseline integration. Keep the scanner's exact non-secret settings in `configuration`,
including model revision if applicable. Do not substitute the human label rationale for a scanner
reason. If a scanner supplies no explanation, state that explicitly in `reasons`.

Decisions are `allow`, `block`, or `review`. Normalize unavailable/error results to `review` and retain
the error. Incomplete coverage cannot be exported as an unqualified `allow`; use `review`, retaining
any raw fail-open behavior in the reasons for investigation. A confirmed block may also carry
incomplete coverage. This makes the comparison about usable decisions while preserving failures as
evidence. The tool checks the export's consistency, not whether the baseline execution really occurred.

The runner rejects duplicate, missing, or extra IDs, altered bytes, mismatched roles/sources, mixed
scanner names/versions, unknown labels, and missing scanner configuration. Different configurations
within one scanner version are retained per row, so source-specific policies remain visible.

## Run and inspect

From the repository root, with Rust dependencies already cached and the parent output directory present:

```bash
cargo run --manifest-path crates/eval/Cargo.toml --offline --locked -- \
  replay --cases /tmp/lab-replay/captures.jsonl \
  --baseline /tmp/lab-replay/baseline.jsonl \
  --out /tmp/lab-replay/comparison-01
```

The output directory must not already exist. A run writes:

- `comparisons.jsonl`: one row per input, with both decisions, both scanners' evidence, label rationale,
  content hash, source, caller role, and a disagreement flag.
- `report.md`: counts by source/role, benign blocks and injection allows, unresolved reviews, and every
  capture's decisions and reasons. Agreements remain visible so shared mistakes are not hidden.
  Long explanations are marked as shortened; JSONL retains the evidence.
- `run.json`: capture-manifest, baseline-export, and replay-executable SHA-256 hashes. The executable
  hash distinguishes local builds even when package versions have not changed.

Exit 0 means the replay completed, including when scanners disagree. Exit 1 means the replay failed.
This is an exploratory comparison, not a release gate. Counts apply only to the selected set and do
not establish population accuracy or latency. No real lab result is claimed by the synthetic tests.

Review disagreements alongside label rationales before changing rules. Also inspect agreements that
contradict the labels: both scanners may miss an injection or flag a legitimate security lesson.
Any rule change suggested by these cases needs separate held-out inputs to test whether it generalizes.

## Instrument validation

```bash
cargo test --manifest-path crates/eval/Cargo.toml --offline --locked replay
```

The synthetic tests cover paired source contexts, disagreements and label counts, exact-byte hashing,
failed joins without partial reports, incomplete/error handling, escaped report text, refusal to
overwrite results, and mixed scanner versions. They do not run the user's existing scanner.

## Optional export-policy experiment

`replay --export-policy PATH.toml` enables the same caller-owned permissions as `plz scan`. The effective permissions and rule identity are retained in verdicts and `run.json`; omitting the flag preserves the earlier structural-only replay. See [the measured experiment](../../docs/research/action-evidence-shart-2026-09-10.md).
