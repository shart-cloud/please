# Decision-model proof of concept — 2026-09-16

GLiClass Small ran locally at useful latency, but the tested zero-shot decision recipes are not suitable for Please's security decisions. The decomposed arm flagged essentially every completed benign case, and its contextual arm classified every candidate as reference material regardless of authorization. Keep the architecture experiment; reject this recipe at its frozen operating point.

## Measured comparison

One pinned GLiClass checkpoint, binary and decomposed recipes, CPU and GPU; compared with the current shipping structural detector and structural + ProtectAI. 600 exposed public cases plus 30 first-party artifact cases and 90 paired contextual cases. No remote judge or fine-tuning. This is development evidence, not independent holdout performance.

The table preserves source strata. Each public source/label cell has 100 inputs; the first-party attack row has 30. GLiClass CPU/GPU artifact decisions and coverage agreed on all 630 cases in both recipes.

| Source / endpoint | Structural | Structural + ProtectAI | GLiClass binary | GLiClass decomposed |
|---|---:|---:|---:|---:|
| Gandalf-Ignore attacks detected | 60/100 | 100/100 | 78/100 | 100/100 |
| jayavibhav-PI attacks detected | 9/100 | 97/100 | 87/100 | 100/100 |
| safe-guard-PI attacks detected | 32/100 | 75/100 | 70/100 | 100/100 |
| First-party pilot attacks detected | 4/30 | 23/30 | 14/30 | 30/30 |
| OR-Bench false positives | 0/100 | 4/100 | 27/100 | 100/100 |
| jayavibhav-PI false positives | 2/100 | 70/100 | 62/100 | 100/100 |
| safe-guard-PI false positives | 0/100 | 0/100 | 30/100 | 99/100 |

One safe-guard-PI benign input exceeded the candidate's 512-token limit (including labels), so both GLiClass arms abstained on it. The denominator retains that case. The decomposed arm therefore flagged every benign case it completed; the apparent perfect recall is not useful discrimination.

The current baselines were rebuilt from the current source. Historical September 11 ProtectAI metrics have different code/decision behavior and are not substituted here. Baseline classifier admission is 700/1000, with the shipping default ML impact and High action threshold. Candidate scores use a separately declared 0.7 threshold; these are not matched false-positive operating points and are not equally calibrated quantities.

## Context sensitivity

For each of repository-file, tool-response and user-input delivery, the contextual arm scored 10/30 correct (33.3%). It returned `non_instruction` in all 90 cases: 30 aligned, 30 conflicting, 30 quoted/reference. Zero of the 30 three-context groups were entirely correct. The context-blind ablation also scored 10/30 per delivery. Thus this recipe shows no useful contextual discrimination, even on the pilot's conspicuous task templates. Template leakage means even success here would not establish general boundary understanding.

Trusted task and permissions were supplied as input text. Context IDs, ground truth, dataset names and prior detector scores were withheld. Declaring a field trusted in JSON does not establish that a pretrained classifier understands or respects that boundary.

## Local timing

| Arm | GPU median / p95 | CPU median / p95 |
|---|---:|---:|
| Binary | 25.4 / 38.5 ms | 62.8 / 116.6 ms |
| Decomposed, artifact + context | 30.3 / 47.5 ms | 111.9 / 211.8 ms |

Hardware: RTX 3050 Laptop 4 GB; i9-12900HK through WSL, 8 logical CPUs exposed. PyTorch float32, 4 CPU threads, batch size 1. Timing includes tokenization and returning scores to CPU, excludes model loading/hashing and one warmup. It is one sequential pass, not a repeated latency study. Model/backend/device differences prevent treating this as an architecture-controlled speed comparison.

The shipping CLI took 0.086 seconds for the structural batch and 199.217 seconds for structural + ProtectAI over 630 documents, including load/output. Those totals are not directly comparable to warm model-call percentiles.

## Validation and evidence

Seven contract tests passed, including 1,000 randomized score sets with missing-field checks. Real-weight scores matched the official GLiClass pipeline for all three question sets. Real inference refused token overflow and injected label markers. Both completed bench runs passed the canonical saved-output verifier; the report recomputed baseline decisions from native verdicts and confirmed CLI/in-process structural agreement.

The first GPU attempt failed during warmup because the adapter omitted `max_num_classes`. It produced no candidate predictions. The failed run is preserved. The corrected run kept the same weights, questions and thresholds. This was an integration fix, not post-result tuning.

- [Reproduction and code](../../crates/eval/scripts/decision_poc/README.md)
- [Pre-inference plan](../../crates/eval/scripts/decision_poc/PLAN.md)
- [Pinned inputs, assets, runtime and measured summary](decision-model-poc-2026-09-16.json)
- Local complete report: `.cache/decision-poc-20260916/report.html`
- GPU native evidence: `.cache/decision-poc-20260916/run-cuda0-v2/`
- CPU native evidence: `.cache/decision-poc-20260916/run-cpu/`
- Native shipping baseline: `.cache/decision-poc-20260916/baseline/`

No shipping crate, dependency, rule, or policy was changed. Public corpus text and weights remain in ignored caches. The checked-in-compatible manifest contains IDs, labels and hashes, not corpus text. Live LLM judge comparison, calibration, multilingual attacks, long-document windowing for the candidate, and an untouched owner-labeled holdout remain unmeasured.

## What to try next

The next useful experiment is an entailment-oriented model or a small model fine-tuned on explicitly labeled boundary questions. Freeze a false-positive budget, include unknown/insufficient-context answers, and measure whether it distinguishes authorization changes before testing its authority to clear existing findings. This result does not establish that GLiClass cannot be fine-tuned for the task, that another label recipe cannot work, or that Jev would succeed. It establishes that a general zero-shot classifier plus these natural-language labels is not a drop-in contextual judge.
