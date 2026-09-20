# Phase 2A contextual decision experiment

Human-directed, Codex-authored evaluator-only work. English-only, offline local inference; no enforcement authority, shipping dependency, or cloud training.

## Frozen recipes and contract

`recipes.json` fixes the exact hypothesis order, positive/negative statements, model revisions, transformations, threshold/margin grid and bounds before dataset inference. G1 softmaxes each pair of original logits. N1 retains entailment, neutral and contradiction; N2 retains entailment/not-entailment. Non-entailment never maps directly to conflict. A unique relation must reach the support threshold and margin. Scores are uncalibrated model support, not validated probabilities.

The default point is support 0.7 and margin 0.15. Missing/invalid task or permission structure, empty permission scope, invalid scores, byte/token overflow and special model markers abstain. Nonempty irrelevant permissions require model judgment and are evaluated as missing-scope cases. Evidence is always empty. The harness enforces a 30-second request deadline and 180-second startup deadline; adapter diagnostics retain whole-decision time and raw logits. NLI hypotheses are batched three at a time; G1 scores all six statements in one call.

Model and tokenizer files are hash-checked before loading. The adapter checks recipe and lock hashes supplied in the system manifest. The native runner freezes executable bytes per run. Python/package versions are recorded separately; the interpreter and installed packages are not copied by the native runner. Reproduction therefore requires the recorded runtime, not merely the script. Model inference is declared offline, not OS-network-sandboxed.

## Data and limitations

`prepare.py` produces four cache-only immutable native packs:

- Development: 120 four-context groups, 480 cases, 10 workflow families.
- Calibration: 60 four-context groups, 240 cases, five other workflow families. It uses schema purpose `development`, with its separate calibration role explicitly recorded.
- Shuffled context: 480 pre-outcome, self-reviewed controls. Donor operative tasks concern a different action; analytical donor contexts remain non-operative.
- Challenge: 30 cases covering malformed UTF-8, model markers, byte/token overflow, negation, similar resource names, claimed authority, mixed quoted/operative text, and changed actions under the same fixed context.

Candidate bytes are identical within main groups. Whole workflow families stay in one pack. Cross-pack exact/family overlap and lowercase byte-sequence similarity >=0.8 are rejected. This heuristic does not prove semantic novelty. Delivery variants share wording and workflow templates; the 120 groups are not 120 independent workflows. The same analytical templates appear in both packs. These are intentionally limited development fixtures, not an unseen-template success test.

Labels are Codex-authored and Codex-self-reviewed before outcomes. No owner or independent review is claimed. `review.json` and the complete packs contain reviewable tasks, permissions, labels and provenance. A truly independent 60-group holdout remains uncollected and must not be replaced by these exposed examples.

No new artifact detector was introduced. Phase 1 public-corpus and shipping-detector results remain preserved in their original runs; artifact detectors receive no contextual accuracy score.

## Reproduction

From the repository root in Ubuntu WSL:

```bash
python3 -m unittest discover -s crates/eval/scripts/decision_poc_v2 -v
python3 crates/eval/scripts/decision_poc_v2/fetch_models.py
.cache/decision-poc-venv/bin/python crates/eval/scripts/decision_poc_v2/check_models.py
python3 crates/eval/scripts/decision_poc_v2/prepare.py
crates/eval/target/release/please-eval bench run \
  --experiment .cache/decision-poc-v2-20260916/development-cuda0-pass1.experiment.json \
  --out .cache/decision-poc-v2-20260916/run-development-cuda0-pass1
python3 crates/eval/scripts/decision_poc_v2/review.py
python3 crates/eval/scripts/decision_poc_v2/run_remaining.py
python3 crates/eval/scripts/decision_poc_v2/finalize.py
```

These commands require a fresh output location; preparation and run creation refuse overwrites. The recorded instance is `.cache/decision-poc-v2-20260916`. Use a new explicitly named cache for another experiment and change the scripts' OUT constant together. Never rerun preparation over the Phase 1 cache. G1 intentionally reuses Phase 1's exact pinned model assets and Python environment; no dependency upgrade was required. New model assets are downloaded only from the two specified public revisions, with configuration/card hashes checked against the prior research record.

The remaining-run script first verifies development evidence and chooses one arm using the frozen rule. It records that selection before opening calibration. Every calibration grid point is retained, including rejected points. An eligible point must meet the observed benign false-conflict budget, answerable coverage and missing-context requirements. No eligible point means no finalist.

CPU/GPU measurements use separate sequential runs, three full passes, a fixed randomized case order, rotating model order, float32/eager inference and four CPU threads. Only one model is loaded by the benchmark at a time. Each process has one startup warmup; length-bucket warmup is not implemented. Background work on this shared machine is separately disclosed. These timings are screening measurements and cannot establish an uncontended deployment budget.

## Retained setup failures

Preflight attempts and original identities remain in the cache. Before any dataset inference, checks caught an overly broad cache-path filter, a cross-pack near-duplicate, absence of pip in the existing environment, a native request/input cap mismatch, and ambiguity in missing-permission task wording. Fixes were made before inspecting dataset outputs. Dependency recording uses importlib metadata rather than changing the environment. ModernBERT reference compilation is explicitly disabled. Official-path parity was rerun on the final implementation.

## Next decision

Review the generated source-stratified report. Stop the zero-shot recipe if quality or calibration gates fail; do not relax the frozen gates. Independent label review comes before interpreting a failure as a need for fine-tuning. Conditional Colab training remains a separate phase: no account access, data upload, notebook, weights or training run is claimed here.

The shuffled pack retains 120 disputed broad-task donor labels discovered during later semantic self-review. The report excludes these mappings, keeps their identities and the original outcomes, and does not assert replacement labels. This post-outcome audit is not independent validation. See shuffled-label-disagreements.json.

The finalizer runs exact 512/513-token checks after inference timings, verifies every native run, and writes the research report and Windows preview. A same-limit ModernBERT GPU retry follows a failed third pass when needed; it never replaces that failed run.
