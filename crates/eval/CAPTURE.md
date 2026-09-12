# Collect and freeze a fresh owner-labeled set

For evaluation from published corpora, use [the dataset workflow](DATASETS.md). It inherits upstream
labels and records their limits; live captures and owner relabeling are not prerequisites for that work.

`please-eval capture freeze` packages reviewed local inputs for the existing replay runner. It does
not run a scanner, display payloads, assign labels, or contact a service. `capture check` verifies
the package against a digest retained separately. Actual captures, labels, and packages belong under
the ignored `.cache/` directory or another private local directory.

The September 10 lab captures and all 60 authored action-evidence cases are development evidence.
The authored challenge split is exposed. Passing its regressions cannot establish generalization.

## Collection protocol

Before collecting, record the application task, scanner boundary, caller-owned export permissions,
collection period, sampling rule, and stopping rule in `protocol`. Preserve the exact bytes passed
to the scanner, including its envelope and newlines. Record the source and role supplied by the
caller. A payload claiming to be trusted cannot choose its own source.

Aim initially for 24 fresh cases: four benign and four injection cases per source, drawn from
`untrusted_user_input`, `untrusted_tool_response`, and `security_reference`. This is a purposive
coverage target, not a representative sample or a release-quality estimate. If actual traffic lacks
one population, report that absence rather than inventing a capture. Legitimate security material
should include examples that quote attacks within the real task. Label an instruction in that source
as injection only when the task context justifies it.

An application owner reviews each input against the intended task and permissions, without seeing
detector outcomes, and assigns `benign`, `injection`, or `uncertain` with a rationale. The tool records
the declared reviewer; it cannot authenticate them or prove that they were blinded. Do not replace an
uncertain label with a confident one to reach a target count. Redaction or rewriting creates a new
input that needs a new hash and label review; record that transformation in `provenance`.

Assign whole conversations, attack families, and near-duplicate clusters to one `group` and one split.
Use `development` for anything already examined during implementation. Use `holdout` only for fresh
cases. Existing development data can stay in its current location; a new collection can contain only
holdout cases. The implementer should not read the holdout payloads or outcome report until the
candidate code/configuration is fixed. After inspecting holdout outcomes, treat that set as exposed
for subsequent tuning and include its manifest in the next freeze's exclusions.

## Reviewed collection format

Start from [capture-template.json](capture-template.json), copying it into your private collection
directory. Fill the top-level fields and add one object like this to `cases` for each actual capture:

```json
{
  "capture": {
    "id": "tool-001",
    "input_path": "inputs/tool-001.bin",
    "input_sha256": "REPLACE_WITH_SHA256_OF_REVIEWED_BYTES",
    "source": "untrusted_tool_response",
    "control_role": "tool",
    "label": "uncertain",
    "label_reason": "REPLACE_WITH_OWNER_RATIONALE"
  },
  "group": "REPLACE_WITH_CONVERSATION_OR_FAMILY_ID",
  "split": "holdout",
  "provenance": "REPLACE_WITH_CAPTURE_BOUNDARY_AND_TIME",
  "task_context": "REPLACE_WITH_ACTUAL_TASK_AND_APPLICABLE_PERMISSIONS",
  "labeler": "REPLACE_WITH_REVIEWER_IDENTIFIER",
  "previously_exposed": false
}
```

This is a schema illustration, not an owner label or a real capture. Relative input paths resolve
against the draft's directory. Use `sha256sum` to record input identity before label review. Keep
credentials out of metadata; use local reviewer identifiers and provenance references as needed.

Set `export_policy_path` to the application's actual TOML permissions, relative to the draft, for an
export-detector experiment. The tool validates and copies that exact policy into the frozen package.
Use `null` for structural-only evaluation. Use separate collections for different export policies;
the replay runner applies one policy per invocation. `task_context` explains legitimate actions but
is label metadata, not an additional scanner input.

## Freeze and verify

From the repository root, after the owner has completed `.cache/fresh-evaluation-20260911/draft.json`:

```bash
cargo run --manifest-path crates/eval/Cargo.toml --offline --locked -- \
  capture freeze \
  --draft .cache/fresh-evaluation-20260911/draft.json \
  --exclude .cache/lab-replay/shart-ai-20260910/captures.jsonl \
  --exclude tests/fixtures/action-evidence/experiment.jsonl \
  --out .cache/fresh-evaluation-20260911/frozen-01
```

Add another `--exclude` for every other exposed replay manifest or authored JSONL set. Each exclusion
row must contain either a lowercase `input_sha256` or a `text` string. An empty, missing, or malformed
exclusion fails the freeze. The command checks exact content overlap regardless of source or role.
It cannot detect paraphrases or unrecorded prior exposure; owner grouping and exposure declarations
remain necessary.

The freeze rejects changed input bytes, missing review metadata, duplicate IDs, duplicate
input/source/role triples, and groups or identical bytes assigned across splits. Holdout cases must
not be declared exposed or match the exclusion history. A minimum coverage check requires a benign
control in each of the three sources and at least one injection overall. This minimum makes gaps
visible and is much smaller than the collection target; it proves no statistical adequacy. Uncertain
cases remain included but cannot satisfy those minimum counts.

The output directory must be new and its parent must exist. A successful freeze writes:

- `collection.json`: reviewed labels, provenance, groups, protocol, and relocated input paths.
- `development/captures.jsonl` and `holdout/captures.jsonl`: existing replay format, with exact-byte
  snapshots under each split's `inputs/`. The development manifest can be empty.
- `export-policy.toml`, when supplied: the frozen caller-owned permissions.
- `known-exposed.json` and `exclusions/`: excluded content hashes and source-manifest digests.
- `freeze.json`: every output file's SHA-256, original draft and executable digests, freeze time,
  and observed counts by split/source/label. It is written last; interrupted output is incomplete.

Retain the printed **freeze SHA-256 separately** before tuning. To verify later:

```bash
cargo run --manifest-path crates/eval/Cargo.toml --offline --locked -- \
  capture check --dir .cache/fresh-evaluation-20260911/frozen-01 \
  --sha256 REPLACE_WITH_SEPARATELY_RETAINED_FREEZE_DIGEST
```

Check validates all listed artifacts, including labels and permissions. It does not authenticate the
owner, establish semantic novelty, or prevent an authorized person from changing files. Extra files
are outside the freeze and are not verified. Keep results in a separate directory. A modified package
must not be presented under its old digest; changing labels after inspecting results ends blinding.

## Evaluate once the candidate is fixed

First record the candidate commit (and any working-tree changes), build identity, thresholds, and
permissions. Run `capture check` with the retained digest. Then use
[the existing replay procedure](REPLAY.md#existing-scanner-export) to obtain real baseline results
on those same frozen bytes and caller roles. Never fabricate baseline decisions from labels.

```bash
cargo run --manifest-path crates/eval/Cargo.toml --offline --locked -- \
  replay --cases .cache/fresh-evaluation-20260911/frozen-01/holdout/captures.jsonl \
  --baseline /path/to/actual-baseline.jsonl \
  --out .cache/fresh-evaluation-20260911/comparison-01
```

For an export-policy collection, add
`--export-policy .cache/fresh-evaluation-20260911/frozen-01/export-policy.toml`.
The replay command itself does not verify the freeze digest or enforce policy selection; the check
and the selected frozen policy are explicit steps. Inspect errors and agreements as well as
disagreements, report counts by source, and exclude uncertain labels from error rates.

The next detector experiments target renamed variables, unfamiliar export wording, and unrelated
read/export operations. Develop against exposed examples, retain existing defenses, and use the
fresh holdout once the candidate is fixed. A local-ML CLI or measured Wasm integration can proceed
independently, but neither substitutes for this evaluation. The revised judge prompt needs its own
measurement; these commands make no live judge calls.
