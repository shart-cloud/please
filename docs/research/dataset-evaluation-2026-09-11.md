# Dataset evaluation — September 11, 2026

These are preserved pre-change results. The [presentation-only comparison](decision-semantics-2026-09-11.md)
subsequently separates displayed excerpts from coverage without changing this run's decisions.

Completed structural and structural-plus-local-ML scans on all 600 frozen direct prompts. The set contains 300 upstream-labeled injections and 300 benign controls. No detector rules or thresholds were changed after viewing these outcomes.

Adding ML raised High-threshold attack recall from **33.7% to 88.0%**, while raising the benign block rate
from **0.7% to 21.0%**. It recovered 163 previously allowed attacks, introduced 61 additional benign
blocks, and sent another 8 attacks and 11 benign prompts to review. These results do not support
enabling this ML configuration for automatic blocking. Structural detection also misses too many attacks
to claim adequate coverage from this benchmark.

## Decisions at the fixed High threshold

“Block” means a risk finding at High or Critical (score ≥70). “Review” means a lower-band finding or incomplete analysis that does not already qualify for block. “Allow” requires a complete Clean verdict. These are evaluation decisions; the CLI only reports findings.

| Configuration | Attack block | Attack review | Attack allow (miss) | Benign block | Benign review | Benign allow |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Structural | 101 | 0 | 199 | 2 | 0 | 298 |
| Structural + local ML | 264 | 8 | 28 | 63 | 11 | 226 |

Each label column group has a denominator of 300. Block recall and benign block rate are conditional on these benchmark labels; review cases are reported separately.

If both block and review require user intervention, structural-plus-ML interrupts **74/300 benign
inputs (24.7%)**. Removing a block is not necessarily the same as allowing the input without review.

## Source breakdown

Every row has 100 cases. “Findings” includes all risk bands; it is distinct from a High-threshold block.

| Source | Label | Structural block / review / allow | ML combined block / review / allow | Structural findings | ML combined findings |
| --- | --- | ---: | ---: | ---: | ---: |
| Gandalf-Ignore | injection | 60 / 0 / 40 | 100 / 0 / 0 | 60 | 100 |
| OR-Bench | benign | 0 / 0 / 100 | 3 / 1 / 96 | 0 | 4 |
| jayavibhav-PI | benign | 2 / 0 / 98 | 60 / 10 / 30 | 2 | 70 |
| jayavibhav-PI | injection | 9 / 0 / 91 | 96 / 1 / 3 | 9 | 97 |
| safe-guard-PI | benign | 0 / 0 / 100 | 0 / 0 / 100 | 0 | 0 |
| safe-guard-PI | injection | 32 / 0 / 68 | 68 / 7 / 25 | 32 | 75 |

## Coverage and attribution

All 1,200 verdicts passed the published JSON schema. The runner checked one result per frozen capture, exact input hashes and byte lengths, caller source, and model attribution. Local inference returned model reports for all 600 cases. Structural scanning had no coverage gaps.

| Configuration | Label | Cases with gaps | Causes (cases per cause) |
| --- | --- | ---: | --- |
| structural | injection | 0 | none |
| structural | benign | 0 | none |
| structural_ml | injection | 78 | excerpt_length: 78 |
| structural_ml | benign | 49 | excerpt_length: 49 |

Gap counts overlap decisions: a High risk finding remains a block even with a gap. `excerpt_length` records truncation of the displayed finding excerpt at 256 bytes; the ML tier classifies the full document using token chunks and maximum-score pooling. Its document-wide span does not localize an attack.

## Frozen configuration and reproduction

- Dataset preparation, source revision, strata, and exclusion method: [DATASETS.md](../../crates/eval/DATASETS.md).
- Caller source: `untrusted_user_input`; role: `user`; all structural classes enabled; quote suppression disabled by source policy.
- Built with `cargo build --release --locked --offline -p please-cli --no-default-features --features ml-candle`.
- Model: `protectai-deberta-v3-small`, revision `d7c8842daf06de3179cc3aca76b7b3a057acc5e7`; malicious label 1; context 512 tokens; fixed classifier threshold 700/1000.
- The classifier threshold is an experimental configuration, not a calibrated deployment threshold. Its probability maps to finding severity; it is not the final risk band.
- No judge requests or application-specific export permissions were used.

The [machine-readable result](dataset-evaluation-2026-09-11.json) retains binary, source-manifest, model-file, freeze, and result hashes, timings, and aggregate counts. The source manifest captures the uncommitted implementation in addition to Git HEAD.

Local artifacts are under `.cache/dataset-evaluation-20260911/evaluation-01/`: `run.json` retains the exact argument vectors, `ml-config.json` the model configuration, `source-files.json` the source hashes, and each configuration has full verdicts and payload-free per-case decisions. The local runner is `.cache/dataset-evaluation-20260911/run_evaluation.py`; it refuses to overwrite its output directory. Raw prompts and finding excerpts stay in ignored local files.

## Interpretation and next use

The largest precision problem is concentrated in jayavibhav-PI: ML combined blocks 60/100 benign
prompts there, compared with 3/100 in OR-Bench and 0/100 in safe-guard-PI. Review those false positives
and the 28 remaining allowed attacks as development cases before proposing a detector or threshold
change. Do not silently relabel disagreements to improve reported accuracy. Revised-judge evaluation
remains a separate pending experiment.

Follow-up [source-specific diagnosis](dataset-diagnosis-2026-09-11.md) records a blinded mixed review,
exact token/chunk measurements, and the prepared revised-judge comparison. Live judge results remain
pending credentials; no detector tuning followed these analyses.

This is a within-source holdout from indexed local experiments, using inherited dataset labels. The balanced sample does not estimate deployment prevalence. Model-training overlap, semantic overlap, and upstream label errors remain possible; no owner adjudication was performed. It supplies no fresh tool-response, security-reference, or application-permission evaluation.

**These 600 cases are now exposed.** Keep them as a development/regression set for subsequent tuning, exclude their exact and normalized hashes from the next holdout, and collect another untouched set before claiming a tuning improvement. `exposure.json` records evaluation separately from the immutable freeze; the freeze’s `detector_run: false` describes preparation time.
