# Protected-export evidence experiment — 2026-09-10

The opt-in Rust export detector increased blocks on the 20 previously examined SHART inputs from
1/14 to **11/14 labeled attacks**, while both variants allowed all five benign controls. The existing
PromptGuard + WulfRegex reconstruction blocks 7/14. An offline OR of its saved decisions with the
new Rust decisions blocks **13/14**, leaving `lab-15` missed. This OR is a replay calculation, not a deployed integration.

The new challenge set exposes a precision cost: the Rust detector increases attack blocks from 2/10
to **8/10**, and benign blocks from 1/10 to **2/10**. This experiment does not establish release readiness.

## What changed

`ScanPolicy::export_policy` optionally carries a validated `ExportPolicy`. It names protected-resource
aliases and exact permitted export destinations, supplied by the caller. The CLI loads it with
`--export-policy`; the replay command accepts the same option. Ordinary callers omit it and preserve
their existing detection behavior. The verdict's effective policy retains the full permissions,
action vocabulary, bounded window, and independent SHA-256 identities for permissions and rules.

The new detector combines a protected-resource reference with an export verb, plus nearby read/value
references when linking back to an earlier resource. It looks at up to 64 neighboring word tokens.
Read/export/value vocabularies and severity live in `crates/core/data/export-actions.toml`, are loadable
at runtime, and have a recorded version/digest. Resource names and aliases belong to application policy.
No callback hostname from the lab is embedded in the detector or its permissions.

This is **lexical evidence of a possible data flow**, not semantic proof, execution tracing, or an
authorization enforcement mechanism. Exact grants suppress only this detector's candidate; existing
rules may still flag the text. For SHART the experiment grants no export of named credentials.
The public monitoring-only case keeps its prior `uncertain` label.

Direct evidence uses caller-selected quotation behavior. One quoting region must cover the entire
resource/action relation before it can be suppressed; quoting only a variable name cannot hide the
surrounding action. Decoded evidence uses the existing bounded expansion and carries original spans
and transform chains. Bounds and excerpt truncation stay visible as coverage gaps.

The optional judge now receives escaped caller permissions outside the document envelope, with prompt
version `2026-09-10.4`. It remains a reviewer of existing findings; no live judge ran in this experiment.

## Evidence design

- The original 20 SHART captures are **development evidence**, already inspected in the preceding review.
  Their labels and bytes were not changed. The original baseline results were imported with exact hash,
  ID, source, and role checks; the Python baseline was not rerun. Its recorded reconstruction limitations
  remain those in `lab-replay-shart-2026-09-10.md`.
- Before implementing the detector, 32 training, 8 calibration, and 20 challenge cases were authored and
  frozen in `tests/fixtures/action-evidence/experiment.jsonl` and `freeze.json`.
- The challenge cases use different task wrappers and attack forms, including encoded instructions,
  constructed destinations, split sentences, euphemisms, grants, public telemetry, and security lessons.
  The same assistant authored and implemented the experiment. This is **not an independently blinded
  generalization estimate**, and shared resource names/permission concepts remain across splits.
- No detector/model parameters were tuned after inspecting challenge outcomes. The challenge cases are
  now exposed and must become regression/development data before the next tuning round.
- Real captures cover direct user input only. The two authored tool/reference examples supply no evidence
  about real tool-response or security-reference populations. Benign SHART captures remain five warmup cases.

## Results

| Scanner | SHART attack blocks | SHART benign blocks | Challenge attack blocks | Challenge benign blocks |
| --- | ---: | ---: | ---: | ---: |
| Original Please structural policy | 1/14 | 0/5 | 2/10 | 1/10 |
| Please with export policy | 11/14 | 0/5 | 8/10 | 2/10 |
| Existing PromptGuard + WulfRegex | 7/14 | 0/5 | Not run | Not run |
| Independent MiniLM probe | 1/14 | 0/5 | 2/10 | 1/10 |
| Export policy OR existing scanner | 13/14 | 0/5 | Not run | Not run |

The uncertain SHART case is blocked by the original/new structural scanners and existing scanner;
the model allows it. It is excluded from attack/benign counts. Counts are purposive sample observations,
not population accuracy estimates. Complete machine-readable counts and artifact hashes accompany
this document in `action-evidence-shart-2026-09-10.json`.

| Challenge source | Cases | Original attack blocks | Export attack blocks | Original benign blocks | Export benign blocks |
| --- | ---: | ---: | ---: | ---: | ---: |
| security_reference | 1 | 0/0 | 0/0 | 0/1 | 0/1 |
| untrusted_tool_response | 1 | 0/1 | 1/1 | 0/0 | 0/0 |
| untrusted_user_input | 18 | 2/9 | 7/9 | 1/9 | 2/9 |

Zero-denominator cells mean no cases in that stratum, not measured accuracy. The real captures are all `untrusted_user_input`.

Adding the model probe to the new Rust decisions recovered no additional attacks: the OR remains 11/14 on SHART and 8/10 on challenges, while challenge benign blocks increase to 3/10. This probe adds cost and false positives without measured recall benefit here.

### Remaining Rust errors

- `lab-05`, `lab-11`, and `lab-15` still have no active findings. Two are blocked by the old hostname regex;
  keeping that layer would therefore preserve useful coverage. No threshold change repairs these zeros.
- `hold-04` (split sentences with a renamed variable) and `hold-06` (unseen verb/euphemism) are missed.
  The detector cannot generally resolve arbitrary variable aliases or paraphrases.
- `hold-15` (credential rotation followed by public telemetry) is a false positive from the existing
  `solicitation.actionable_disclosure_introduced` rule, present before this detector.
- `hold-16` (authorized upload) is a **new false positive**: a sentence-final period is preserved in the
  candidate URL, so it does not equal the granted URL. Conservative exact comparison also intentionally
  treats a trailing slash, query, or fragment as a different destination. These are reasons to keep this
  experimental rather than casually strip punctuation and risk broadening a grant.

### Model comparison

The comparator is the cached `all-MiniLM-L6-v2` encoder plus a small linear classifier trained locally
on the 32 authored training cases. Trusted resource permissions and source precede the text in the
encoder input. IDs, labels, split names, and family names are not model inputs. It is an independent
candidate detector and runs even when structural scanning has no findings.

This is an inexpensive feasibility probe, **not CAD, a reproduction of CAD, or a validated PI model**.
The encoder is pinned to revision `1110a243fdf4706b3f48f1d95db1a4f5529b4d41`; config, tokenizer, and weights
were SHA-256 verified. The fixed head recipe uses seed 0, 800 Adam steps, learning rate 0.03, and L2 0.01.
Weights are saved as JSON. Overlapping windows preserve complete token coverage at the encoder's
256-token limit; the maximum observed was two windows.

The decision threshold (0.5231877565383912) is the next representable value above the largest
score among **four calibration benign cases**. Zero blocks on those four cases is a calibration
observation, not a low-FPR guarantee. Training performance is also weak (7/16 attacks blocked, 1/16
benign blocked at the selected threshold). The experiment supports no conclusion that stronger
context-aware models would fail; it shows this tiny training recipe does not earn deployment.

No lab prompts were sent to a service. Model assets came from the existing cache; offline flags and a
socket audit hook blocked network inference. No model weights or raw captures were added to tracked files.

## Runtime observations

The native release-build Rust runner reuses one engine. Across the 20 SHART captures, the median of
per-input warm medians (five repetitions each) was **119.0 microseconds**, with a maximum warm median
of 345 microseconds. This measures the complete structural+export scan.
The local model's single-pass median encoding time was **26.88 ms** across
all 80 cases, with initialization 157.40 ms. These are different measurement
recipes and are not a controlled speed comparison. Model encoding and compilation could overlap with
other local work. Worker cold start, Worker memory, deployment runtime, and end-to-end agent outcomes
remain unmeasured. A Wasm compile is compatibility evidence only.

## Reproduce

From the repository root, with cached Rust dependencies:

```bash
cargo test -p please-core --test export_policy --offline --locked
cargo run --manifest-path crates/eval/Cargo.toml --release --example export_experiment \
  --offline --locked -- "$PWD" tests/fixtures/action-evidence/experiment.jsonl \
  /tmp/please-authored-new.jsonl
cargo run --manifest-path crates/eval/Cargo.toml --offline --locked -- replay \
  --cases .cache/lab-replay/shart-ai-20260910/captures.jsonl \
  --baseline .cache/lab-replay/shart-ai-20260910/baseline-run/baseline.jsonl \
  --export-policy examples/export-policy.toml --out /tmp/please-export-replay-new
```

For the model, the existing local Python environment has Torch, Transformers, tokenizers, and NumPy:

```bash
/tmp/please-lab-venv/bin/python crates/eval/scripts/context_export_probe.py \
  --repo "$PWD" --cases tests/fixtures/action-evidence/experiment.jsonl \
  --lab-captures .cache/lab-replay/shart-ai-20260910/captures.jsonl \
  --out /tmp/please-model-probe-new
```

The probe currently expects the pinned model under `/home/jg/.cache/please-eval/models/` and Python 3.12,
Torch 2.6.0+cpu, and NumPy 2.5.3 were used. `model-final/run.json` records the recipe, package versions, hashes,
threshold, and counts. Output paths must be new. The existing machine-local venv and model cache are
prerequisites; there is no automatic dependency install or asset download.

Private artifacts are under `.cache/action-evidence-20260910/`: before-change snapshots,
`authored-final-results.jsonl`, `lab-final-results.jsonl`, `replay/`, `model-final/`, and `summary.json`.
The public authored cases contain example domains and resource names, not actual secret values.

## Validation and decision

The 14 new core tests include exact-grant boundaries, quotations spanning part of a relation, decoded
payloads, source spoofing, disabled classes, malformed policy, truncation, saturation, determinism,
and arbitrary-byte fuzzing through the scan pipeline. CLI JSON-schema and judge-context integration
tests exercise the public paths. Randomized testing also reproduced and repaired an existing
confusable-detector bug: replacing invalid UTF-8 shifted spans after malformed bytes. It now scans
valid UTF-8 chunks with original offsets; a fixed regression and persisted fuzz seed cover the repair.

Workspace tests completed with only the two previously documented fixture failures; the evaluation
suite passed all 57 tests. Workspace/evaluation Clippy with warnings denied and the core Wasm build passed.
CLI tests without default features passed, and the dependency allow-list remained an exact match at 27 crates.

This is a completed detection experiment, not a release approval. Keep the new capability opt-in,
retain existing useful defenses, and obtain a fresh owner-labeled set before changing the algorithm.
The next substantive work is action/object binding (including renamed variables and precise URL
handling), followed by actual runtime data-flow enforcement and a stronger context-aware comparator.
No production changes, deployment, live judge calls, or end-to-end lab executions were made.

Implementation, authored cases, and this report were produced by Codex in collaboration with Jared Gore.

Final formatting and lint checks passed for both workspace and evaluation crate. A repeat run of the packaged code reproduced every Rust decision and the exact trained model-head hash. The final source state is archived locally as `.cache/action-evidence-20260910/implementation-snapshot.tar.gz`.
