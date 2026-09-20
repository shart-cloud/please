# Handoff: lightweight contextual decision models for Please

> Historical Phase-2 planning handoff. Phase 2A, Jev evaluation and the interactive CLI were subsequently completed. Read [the current Jev/TUI handoff](/home/jg/git/bee-swarm/docs/research/jev-next-steps-handoff-2026-09-16.md) for the current state.

**Updated:** 2026-09-16  
**Next step:** implement Phase 2A in the isolated evaluator.  
**Current state:** Phase 1 implemented and benchmarked; Phase 2 researched and planned only. No phase-2 weights, new datasets, training notebook or adapters have been created. No cloud account has been accessed and no data uploaded.

## Objective and agreed direction

Jared wants to explore a lightweight decision model for Please (`plz`, repository name `bee-swarm`) and benchmark it against the existing detector. The key question is whether a small local model can distinguish an instruction that is authorized, one that conflicts with trusted boundaries, and non-operative content when the candidate text stays the same but caller-owned context changes.

Start with contrastive GLiClass, three-way DeBERTa NLI and ModernBERT NLI. Fine-tune a small specialist if the zero-shot results justify further work. Jared has **Colab Pro** available for training. Deployment measurements remain on the local CPU and RTX 3050; training in Colab must not create a cloud dependency at inference time.

This handoff records proposed work. The quality/resource thresholds below are proposed experiment gates, not measured results or established shipping policy.

## Workspace and handoff state

- Repository: `/home/jg/git/bee-swarm` in Ubuntu WSL on Windows.
- Branch observed: `007-Prompt-Injection-Test-Bench`.
- HEAD observed: `40f3395c5e681b9b2135b7afa482df9d43a9bab8`.
- Local hardware: i9-12900HK, WSL exposing 8 logical CPUs; RTX 3050 Laptop with 4 GB VRAM.
- Existing Python environment: `/home/jg/git/bee-swarm/.cache/decision-poc-venv/bin/python`.
- Existing evaluator: `/home/jg/git/bee-swarm/crates/eval/target/release/please-eval`.
- The POC, phase-2 documents and this handoff are **uncommitted**. `docs/attribution.md` is modified; the POC script directory and research documents are untracked. Inspect current status before changing anything. A fresh worktree from HEAD will not contain this work or its ignored caches.

Work on the existing checkout, or explicitly carry its pending files into any isolated checkout. Preserve earlier changes and saved runs. Do not reset/clean the repository, overwrite the POC, or rerun preparation into its existing output directory.

## Read first

1. [Phase-2 plan](/home/jg/git/bee-swarm/docs/research/decision-model-phase-2-plan-2026-09-16.md): full design, data protocol, gates and Colab workflow.
2. [Phase-1 measured report](/home/jg/git/bee-swarm/docs/research/decision-model-poc-2026-09-16.md) and [reproduction README](/home/jg/git/bee-swarm/crates/eval/scripts/decision_poc/README.md).
3. [Research metadata](/home/jg/git/bee-swarm/docs/research/decision-model-phase-2-research-2026-09-16.json): upstream revisions/configuration hashes and saved-score audit.
4. [Constitution](/home/jg/git/bee-swarm/.specify/memory/constitution.md), [bench contract](/home/jg/git/bee-swarm/crates/eval/BENCH.md), [capture discipline](/home/jg/git/bee-swarm/crates/eval/CAPTURE.md), and [context label guide](/home/jg/git/bee-swarm/specs/007-prompt-injection-test-bench/label-guide.md).

## What we already learned

Phase 1 used `knowledgator/gliclass-small-v1.0`, pinned to `21edefaf7951f68c68c505f9139ba536d3b448f7`, with 600 exposed public cases plus 30 artifact and 90 contextual pilot cases.

- Binary GLiClass had high false-positive rates: 27/100 on OR-Bench, 62/100 on jayavibhav benign, and 30/100 on safe-guard benign.
- Decomposed GLiClass flagged every benign case it completed. One benign input exceeded the token cap and abstained.
- Contextual GLiClass returned `non_instruction` for all 90 cases: 33.3% correct and zero fully correct three-context groups.
- Its independent sigmoid scores all exceeded 0.7. The decoder checked reference first, masking score differences. Raw conflict scores separated the pilot's conflict contexts, but those contexts used conspicuous templates. This is exposed diagnostic evidence, not generalization. Choosing argmax would still mislabel every conflict.
- Binary warm inference: GPU median/p95 25.4/38.5 ms; CPU 62.8/116.6 ms. Decomposed artifact+context: GPU 30.3/47.5 ms; CPU 111.9/211.8 ms. These were single-pass timings and exclude load; they cannot establish a backend-controlled speed advantage over the shipping CLI.

The tested recipe failed. That does not rule out GLiClass with different training or scoring. Preserve the failure and give every new recipe its own identity.

## Reusable evidence and checks

Verified present when writing this handoff:

| Item | Absolute path |
|---|---|
| Complete local HTML report | `/home/jg/git/bee-swarm/.cache/decision-poc-20260916/report.html` |
| Successful GPU run | `/home/jg/git/bee-swarm/.cache/decision-poc-20260916/run-cuda0-v2/` |
| Successful CPU run | `/home/jg/git/bee-swarm/.cache/decision-poc-20260916/run-cpu/` |
| Shipping structural / structural+ML results | `/home/jg/git/bee-swarm/.cache/decision-poc-20260916/baseline/` |
| Existing scripts and weight lock | `/home/jg/git/bee-swarm/crates/eval/scripts/decision_poc/` |
| Windows report preview | `C:/Users/jg/benchmark-preview/decision-model-poc-20260916/report.html` |

The original `run-cuda0` failed during startup because `max_num_classes` was omitted; it produced no candidate predictions. Use `run-cuda0-v2` for measured GPU results, and preserve the failed attempt.

Recorded earlier validation: seven adapter tests including randomized incomplete-score checks, official-pipeline parity, real token-overflow and special-marker refusal, both saved-run verifiers, and structural CLI/in-process agreement. These checks were not rerun merely to write the handoff.

Useful commands inside Ubuntu WSL, from the repository root:

```bash
cd /home/jg/git/bee-swarm
git status --short
python3 -m unittest discover -s crates/eval/scripts/decision_poc -p test_adapter.py -v
```

Optional existing-weight parity check and saved-run viewer:

```bash
.cache/decision-poc-venv/bin/python crates/eval/scripts/decision_poc/check_model.py
crates/eval/target/release/please-eval bench view --run .cache/decision-poc-20260916/run-cuda0-v2
```

Do not reinstall the environment or rerun all old inference without a reason. Caches contain weights and licensed corpus text absent from a fresh clone. Missing assets must be reported explicitly, not silently replaced with different data or a smaller sample.

## Next implementation steps, in order

### 1. Freeze and implement the three recipes

Create `/home/jg/git/bee-swarm/crates/eval/scripts/decision_poc_v2/`. Keep everything in the evaluator; no shipping Rust changes are needed.

Write the recipe manifest and expected contract tests first. Freeze exact statements, hypothesis order, logit transformations, abstention rules, threshold-search grid, byte/token bounds and timeout. Record new executable and asset identities.

| Arm | Model / inspected revision | Important implementation detail |
|---|---|---|
| G1 | Existing pinned GLiClass | Three positive/negative statement pairs; use original logit differences and pairwise softmax. Never softmax already saturated sigmoid scores. |
| N1 | `MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli` / `6f5cf0a2b59cabb106aca4c287eed12e357e90eb` | Three NLI outputs: entailment, neutral, contradiction. Score each relation hypothesis against the fixed context/candidate premise. |
| N2 | `MoritzLaurer/ModernBERT-base-zeroshot-v2.0` / `d421c4545a438fd006fb43f8b981c5d908faa1e1` | Two outputs: entailment/not_entailment. Lack of entailment must not be interpreted as conflict. |

Pin and hash actual model/tokenizer files before running. Use a separate dependency lock/environment if new dependencies conflict with the existing POC. Reuse `please-bench-jsonl/v1`, the native contextual normalizer and immutable saved-run verification.

Retain raw logits/scores and complete decision timing. Require a unique supported relation; incompatible evidence, insufficient margin, missing relevant context, invalid scores or overflow produce indeterminate. Assert official-model output parity, label maps, malformed-input handling and bounds. Keep evidence empty unless exact validated spans are actually available.

**Done when:** the three adapters and frozen configs pass contract/parity checks on exposed development fixtures. No claim of effectiveness yet.

### 2. Prepare development data and a separate calibration pack

Proposed main allocation: 120 development groups / 480 cases, 60 calibration groups / 240 cases, and later 60 independent holdout groups / 240 cases. These cases do not exist yet.

Each main group keeps identical candidate bytes across aligned, conflicting, non-operative and insufficient-context variants. Cover user input, repository files and tool responses. Include changes to destinations, resources, action scope, negation and authority; avoid task prefixes that directly reveal labels.

Add candidate-only, context-only and reviewed shuffled-context controls. Also test fixed context with changed candidate actions; those belong to separate groups sharing a family, because the pack requires identical bytes within each group. Include quoted attacks mixed with operative redirection, special tokens, malformed input and over-cap tails.

The schema has only `development` and `holdout`. Represent calibration as a separate immutable development pack, explicitly named in experiment metadata. Enforce family and near-duplicate separation across packs. Missing-task rejection is a contract test; absent relevant permissions can be represented in valid contextual cases.

Record authorship and label review. Self-authored/self-reviewed examples are development evidence. Prepare review materials early; the independent holdout must be collected/reviewed without detector outcomes and stay unread by the implementer until the finalist is frozen.

**Done when:** development/calibration packs, provenance, controls and cross-pack exclusion checks are reviewable and reproducible. Independent collection may remain an explicitly recorded later dependency.

### 3. Compare, calibrate and publish the development result

Run G1/N1/N2 and one-sided controls on development data. Keep old models and shipping detectors on supported surfaces only: the shipping artifact detector has no contextual accuracy to compare.

Choose the candidate on development results; select its operating point on calibration using the predeclared grid. Freeze the finalist before holdout. Preserve failures and rejected operating points. Measure whole decisions, including all NLI hypotheses, on local CPU and GPU separately, using repeated interleaved passes.

Proposed gates from the plan:

- Macro recall >=80% per delivery stratum; complete-group correctness >=70%.
- Determinate coverage >=90% on answerable cases per stratum.
- >=10 percentage point macro-recall improvement over the strongest one-sided control.
- Observed false-conflict rate <=1% in each benign calibration stratum; no incorrect determinate result on mandatory missing-context fixtures.
- For advisory integration, zero observed false reassurance on evaluated conflicts, with uncertainty disclosed.
- Warm complete-decision p95 <=250 ms CPU / <=100 ms GPU; GPU peak <=3 GiB; process RAM <=2 GiB; 512 total encoded tokens per model input initially.

Always show denominators, coverage, source strata and group-aware uncertainty. A small set with zero errors does not establish a <1% underlying error rate. Do not silently lower thresholds or coverage requirements after seeing results.

**Done when:** saved runs verify, metrics recompute from native outputs, and a source-stratified report gives a clear go/stop decision. If no candidate passes, report why before trying another model.

## Colab training and integration come later

If labels are sound but zero-shot models fail, compare task-specific fine-tuning with the best frozen baseline. Start with a frozen encoder/head baseline, then encoder tuning; SetFit/MiniLM is a compact alternative. Use training-group learning curves and three fixed seeds.

Prepare a thin `colab_train.ipynb` backed by the versioned training script. Record the actual assigned GPU and available memory, profile a short run, and set a bounded compute budget. Pin code, dependencies, data and weights. Save resumable checkpoints, including optimizer/RNG state, to persistent storage. Keep calibration and independent holdout outside the training inputs. Export weights, tokenizer, label mapping, recipe, logs and hashes; rerun local parity and deployment benchmarks.

Colab account access, assigned hardware and compute balance have not been checked. Existing Pro access informs the plan; it is not a recorded training run.

Any shipping integration follows successful evaluation and begins advisory. The bench context is simpler than the shipping boundary/completeness contract in `/home/jg/git/bee-swarm/crates/core/src/context.rs` and `/home/jg/git/bee-swarm/crates/judge/src/ml_review.rs`. Validate that mapping before integration. Do not grant `MayRelease`, invent evidence spans, infer permissions from absent context, or move ML dependencies into core/default builds.

## Suggested next-task prompt

> Continue the lightweight decision-model experiment in /home/jg/git/bee-swarm. Read docs/research/decision-model-next-steps-handoff-2026-09-16.md and the linked phase-2 plan. Begin Phase 2A with the isolated decision_poc_v2 recipe manifests, contract tests and G1/N1/N2 adapters, then prepare the development/calibration packs and run the bounded development comparison. Preserve the existing uncommitted work, failed recipes and caches. Keep shipping behavior unchanged. Record any independent-label/holdout dependency explicitly; do not claim an unseen evaluation from self-authored or exposed data. Colab Pro is available for the later conditional training phase. Report changed files, validation, measured results and the next decision.
