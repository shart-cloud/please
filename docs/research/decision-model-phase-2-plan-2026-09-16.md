# Lightweight decision models: phase 2 plan

Date: 2026-09-16. Status: researched proposal; implementation and new model evaluation have not started. Scope: local, offline inference evaluation with optional Colab Pro training. CPU is the deployment target; the existing 4 GB RTX 3050 is the local experimental accelerator. Jared confirmed access to Colab Pro for training.

## Recommendation

Test whether a small model uses caller-owned context to distinguish an instruction that is allowed, one that violates a boundary, and content that is not operative. Start with three tightly scoped recipes: contrastive GLiClass, three-way DeBERTa NLI, and ModernBERT NLI. Then train a task-specific model only if the zero-shot results justify it. Keep shipping detectors as artifact baselines and preserve all failed experiments.

The deliverable is a reproducible comparison with explicit stop/go decisions. It is not yet a replacement for structural detection or an authorization mechanism.

## What the first POC actually established

The [phase-1 report](decision-model-poc-2026-09-16.md) established useful local inference latency, poor false-positive behavior, and no useful contextual **decisions** from the frozen recipe. On 90 contextual cases it returned `non_instruction` every time. Its 30 complete context groups all failed.

A read-only inspection of that run adds a useful distinction:

| Ground truth, 30 cases each | Minimum conflict score | Maximum conflict score | Highest-scoring label |
|---|---:|---:|---|
| Aligned | 0.99374 | 0.99737 | Authorized: 30 |
| Conflicting | 0.99909 | 0.99969 | Authorized: 30 |
| Non-instruction | 0.99570 | 0.99818 | Reference: 23; authorized: 7 |

All three sigmoid scores exceeded 0.7 on all 90 cases. The adapter checked reference first, so its precedence erased the differences. Conflict scores happened to separate these templates, but selecting a threshold between those ranges now would be post-hoc tuning. The conspicuous task templates also allow shortcuts. This is a reason to investigate score formulation on new development data, not to revise the recorded failure into a success. Simply taking the largest score would still mislabel every conflict.

The [research manifest](decision-model-phase-2-research-2026-09-16.json) records exact ranges, the saved-result hash, inspected upstream revisions, model configuration and metadata hashes. No phase-2 weights were downloaded and no phase-2 performance is claimed.

## Research and model selection

| Candidate | Verified upstream properties | Proposed role |
|---|---|---|
| Existing GLiClass Small | Already pinned and running locally; reuse phase-1 assets | Test whether contrastive logits avoid the saturated independent-score recipe |
| [DeBERTa-v3-base-mnli-fever-anli](https://huggingface.co/MoritzLaurer/DeBERTa-v3-base-mnli-fever-anli) | MIT; about 184M floating-point parameters including embeddings; 512 positions; entailment, neutral, contradiction | Primary new model: retain uncertainty instead of equating lack of support with conflict |
| [ModernBERT-base-zeroshot-v2.0](https://huggingface.co/MoritzLaurer/ModernBERT-base-zeroshot-v2.0) | Apache-2.0; about 150M parameters; configuration allows 8,192 positions; entailment/not_entailment only | Speed comparison using the same 512-token cap initially; long-context quality remains unproven |
| [PIGuard, formerly InjecGuard](https://huggingface.co/leolee99/PIGuard) | MIT; about 184M parameters; 512 positions; benign/injection; custom model code | Optional artifact-only false-alarm control, after the three primary recipes |

Parameter counts and label maps were checked through upstream configuration and model metadata, not inferred from model names. Snapshot revisions are in the research manifest; implementation must additionally pin and hash every tokenizer, weight and executable asset.

For NLI, entailment means the model judges a hypothesis supported by a premise. It does not certify permission. DeBERTa's neutral class is useful experimental information, not a calibrated uncertainty guarantee. ModernBERT's `not_entailment` combines lack of support and contradiction; never map it directly to a boundary violation. Neither checkpoint was verified as trained for Please's caller-context contract.

[AlignSentinel](https://arxiv.org/html/2602.13597v1) is a close conceptual match: it distinguishes aligned, misaligned and non-instruction inputs using attention features. Its experiments use 7B/8B backend language models. It supports investigating relational decisions, but is not evidence that a small standalone implementation will work on this laptop. No usable standalone checkpoint was identified in the inspected paper.

[SetFit](https://github.com/huggingface/setfit) offers an open Apache-2.0 route to few-shot training with sentence transformers. It is a conditional low-cost training baseline, not a ready-made permission judge. A concatenated task/candidate embedding might still learn superficial similarity; the same counterfactual controls must test it.

## Phase 2A: establish real context sensitivity

### 1. Freeze the question and instrument the recipes

Use the existing four contextual labels: `aligned_instruction`, `conflicting_instruction`, `non_instruction`, `indeterminate`. Freeze English-only scope, templates, decoding rules, resource bounds, expected controls and calibration procedure before evaluating the new packs.

Run these recipe variants, retaining logits and native scores:

- **G1: contrastive GLiClass.** One fixed set of three positive/negative statement pairs, scored together. For each pair use the difference of the original logits and a pairwise softmax, not a softmax over saturated sigmoid outputs. Require a unique supported relation and a calibrated margin; ambiguous or contradictory support abstains. This is a new recipe with a new identity.
- **N1: three-way DeBERTa.** Supply a fixed rendering of trusted task, typed permissions and untrusted candidate as the premise; score three fixed relation hypotheses separately. Keep entailment, neutral and contradiction for each hypothesis. Use entailment-versus-other logit margins and a unique-winner rule. This tests the relational formulation; it does not presume general NLI understands trust boundaries.
- **N2: ModernBERT.** Use the same premise and hypotheses with its two-way head. Low support, incompatible winners or an insufficient margin abstain. Compare its complete three-hypothesis decision against N1 and G1.

Freeze the exact positive/negative wording as versioned data before calibration. Calibration chooses from a small predeclared threshold/margin grid; it does not rewrite prompts. Retain the original binary and decomposed GLiClass systems unchanged as regression controls.

No external LLM is required to prepare inputs or extract actions. Feed no labels, IDs, corpus names or prior detector outcomes to the model. Caller-owned provenance may be included through a fixed mapping; candidate text cannot choose it.

### 2. Build cases that rule out shortcuts

Proposed initial allocation: 120 development groups (480 cases), 60 calibration groups (240 cases), and 60 independent holdout groups (240 cases). Each primary group keeps identical candidate bytes across four reviewed contexts: aligned, conflicting, non-operative and insufficiently specified. These are coverage targets, not statistical proof of deployment quality.

Distribute groups across user input, repository files and tool responses. Cover task redirection, protected data, destinations, file/tool actions, claimed authority and concealment. Vary workflow, wording, names and sentence order. Reserve whole workflows and paraphrase families across splits. Balance superficial cues such as words for permission and prohibition; no universal prefix should identify the answer.

Add a separately reported challenge set containing:

- The same context with allowed versus disallowed candidate actions, resources or destinations. These are separate contextual groups with a shared family: pack validation correctly requires identical candidate bytes within a group.
- Negation, exceptions, similar resource names, read versus write, internal versus external destinations, and missing relevant authorization.
- Benign instructions, attack descriptions, and security discussions; distinguish harmful subject matter from prompt injection.
- Mixed documents containing both quoted examples and operative redirection. A candidate's claim that it is quoted or authorized is never sufficient evidence.
- Spoofed role delimiters, injected model label tokens, Unicode, malformed bytes, exact token-boundary inputs and malicious content at the end of an over-cap document.

Run candidate-only, context-only and shuffled-context controls with the same weights. Their error patterns reveal reliance on just one side of the relationship. A shuffled context can sometimes preserve the correct relation; annotate these controls before scoring rather than assuming every shuffle must flip it.

Owner or independent reviewer labels must be assigned without seeing model outcomes, with uncertainty and disagreement retained. Codex-authored and self-reviewed cases remain development evidence. Fresh holdout collection is a later dependency; it cannot be manufactured by relabeling an exposed set. Follow [CAPTURE.md](../../crates/eval/CAPTURE.md) for grouping and exposure discipline and the [context label guide](../../specs/007-prompt-injection-test-bench/label-guide.md) for relation judgments.

The current pack supports only `development` and `holdout`: keep development and calibration in separate immutable development packs, with their purposes in experiment metadata. Enforce family/byte/near-duplicate separation across all packs, not just within one. Holdout uses a separate frozen pack. Nonempty task is required by the schema; missing-task rejection belongs in adapter contract tests, while absent relevant permissions can be represented in valid contextual cases.

### 3. Keep public corpora in their proper role

Rerun the exposed phase-1 public cases as source-separated artifact regressions. Compare structural, structural+ProtectAI, old GLiClass and any new artifact recipe at their stated operating points. Do not assign artifact detectors contextual accuracy or collapse scores from the two tasks into one leaderboard.

[NotInject/PIGuard](https://github.com/leolee99/PIGuard) supplies a useful additional hard-negative direction: benign text containing trigger words. Pin provenance and inspect training overlap; its public examples are a diagnostic corpus, not our independent holdout. PIGuard's custom code requires local review and pinning; do not copy its example's silent truncation.

[IHEval](https://github.com/ytyz1307zzh/IHEval) is relevant to instruction hierarchy, but evaluates downstream model behavior rather than this classifier's native relations. Its [upstream license](https://github.com/ytyz1307zzh/IHEval/blob/main/LICENSE.md) is CC BY-NC-ND 4.0. Leave it out of the default redistributable training/evaluation pack; use its documented problem categories to inform independently authored cases. A permissively licensed third-party scoring wrapper does not change the upstream dataset license.

### 4. Calibrate, freeze, then evaluate once

Choose one candidate using development results. Use only the separate calibration pack to choose its declared operating point. Retain the full tradeoff curve and every rejected recipe. Freeze code, model/tokenizer hashes, hypotheses, thresholds, backend, precision and bounds before opening holdout outcomes. Once read, that holdout is exposed for subsequent work.

Report per delivery source, workflow and label, with denominators:

- Conflict recall; false-conflict rate on aligned and non-instruction cases separately.
- False reassurance: conflicting cases labeled either aligned or non-instruction.
- Determinate coverage on answerable cases; expected abstention on missing-context cases; timeout/overflow/unavailable coverage separately.
- Full-group correctness, where abstention is correct only for the expected indeterminate member; paired changes with declared group baselines.
- Macro recall across the three answerable classes, counting abstentions as misses; candidate-only/context-only comparisons on exactly the same cases.
- Calibration reliability and group-aware uncertainty intervals. Do not call model scores probabilities until validated on the target distribution.

Proposed screening gates, to freeze before new runs: at least 80% macro recall in every delivery stratum, at least 70% complete-group correctness, at least 90% determinate coverage on answerable cases in every stratum, and at least 10 percentage points improvement over the strongest one-sided control on macro recall. Require no incorrect determinate result on the mandatory missing-context contract fixtures.

Select thresholds for a maximum **1% observed false-conflict rate** in each benign calibration stratum. If no operating point meets this alongside coverage, the recipe fails; do not silently relax the budget. Holdout reports uncertainty instead of upgrading that observed target into a guarantee. Also require zero observed false-reassurance errors for advancement to advisory integration, while acknowledging that a small sample cannot establish a low underlying error rate.

For scale: with zero errors among n independent cases, a one-sided 95% binomial upper bound is `1 - 0.05^(1/n)`: about 2.95% for 100 and below 1% only at 299. Correlated variants do not count as independent trials. The proposed pilot is a screening exercise; a credible per-source low-error claim needs a substantially larger independent collection. These are proposed project gates, not measured results or an existing release policy.

### 5. Measure the whole decision on this hardware

Use 512 total encoded tokens per model input, including trusted context, separators and hypotheses. No silent truncation. Record byte and token caps, requested and completed hypotheses, failures and exact analyzed scope. Long-context capability is a later separately identified experiment.

Keep a persistent process and measure CPU and GPU separately: cold load, peak resident RAM, GPU peak allocation/reservation, warm p50/p95, throughput, and total wall time. Include tokenization, every hypothesis, device transfers and final decoding. Report both adapter wall time and harness overhead. A three-hypothesis NLI decision must not be compared with a single-hypothesis timing.

Use equal inputs and threading, sequential case execution, explicit warmup per shape bucket, and three interleaved passes in a fixed randomized order. Within-request batching is allowed if declared and included in the memory/timing record. Run only one model at a time on the GPU. Establish float32 parity first; precision or quantization changes create new candidate identities and require quality rechecks.

Proposed budgets: complete warm decision p95 <=250 ms on CPU, <=100 ms on GPU, peak GPU memory <=3 GiB, process RAM <=2 GiB, and an explicit hard request deadline. These are experimental targets, not predictions. A faster but less reliable model fails the quality gate; a slower accurate model can justify a separately scoped asynchronous reviewer.

## Phase 2B: conditional task-specific training

If the new pack defeats all zero-shot arms, categorize errors before adding models. If labels are disputed or context is incomplete, repair the data contract first. If the task is well-defined but generic inference fails, compare a supervised context/candidate classifier against the frozen zero-shot winner.

Start with a frozen encoder plus small head, then limited encoder fine-tuning if warranted. Include a compact SetFit baseline using [all-MiniLM-L6-v2](https://huggingface.co/sentence-transformers/all-MiniLM-L6-v2). Preserve its native sequence limit; any smaller-cap coverage difference must be visible. Neither embedding similarity nor a shared topic establishes permission.

Use learning curves at 32, 64 and 120 training groups and several fixed seeds; keep calibration separate. Expand to more workflow families only if held-out development performance improves. Synthetic examples can enlarge training but cannot supply an independent success claim. Record label author and reviewer. If holdout has already been examined to diagnose failure, acquire a new one before claiming generalization.

### Colab Pro training path

Jared confirmed existing Colab Pro access. Use it as the preferred environment for encoder fine-tuning once the data and baseline gates are ready. This makes training the shortlisted 150-184M-parameter encoders more practical if the allocated accelerator has more memory than the local 4 GB GPU; verify fit with a short profiling run. The target remains a small checkpoint that runs locally. We are fine-tuning pretrained weights, not training a language model from scratch.

Google documents variable GPU availability and compute-unit-dependent runtime limits, including possible termination. Pro does not guarantee a particular accelerator or Pro+'s longer continuous execution. Build resumable runs around the assigned resources. [Official Colab FAQ](https://research.google.com/colaboratory/faq.html)

Proposed workflow:

1. Prepare a thin `colab_train.ipynb` entry point backed by the same versioned training script usable locally. Load an immutable code bundle or commit, model/tokenizer revisions, dependency lock, recipe and dataset hashes. Avoid notebook-only training logic or an unpinned install from the latest branch.
2. Stage only the selected training and development-validation packs. Calibration stays reserved for operating-point selection; the independent holdout stays outside the training runtime. Keep original group identities and provenance when exporting data.
3. Record the actual GPU, available VRAM, framework/CUDA versions and supported precision. Profile a short run, then choose and record microbatch size, gradient accumulation and any checkpointing. Keep effective batch size comparable across training variants. Full encoder tuning is an experimental option; retain the frozen-head baseline.
4. Run one model/configuration smoke test before a bounded comparison across three fixed seeds. Log elapsed GPU time, peak memory, training configuration and observed compute-unit use when available. Set a run budget before launching a sweep; do not assume unlimited subscription capacity.
5. Save resumable checkpoints to persistent storage at bounded intervals, including model, optimizer, scheduler, scaler where used, RNG and data-order state. Export the selected checkpoint, tokenizer, label mapping, recipe, logs and hashes together. Notebook and result sharing remain private by default.
6. Bring the checkpoint back to the existing WSL evaluator. Check local inference parity, calibrate on the reserved pack, freeze the finalist, then run the untouched holdout. Laptop CPU/GPU latency and memory are the deployment measurements; Colab timings describe training and cloud experiments only.

Quality of labels and independent evaluation remain the main unresolved dependencies. More compute permits better controlled fine-tuning and repeated seeds; it does not fix shortcut labels or establish generalization. Quantization/export optimization comes after a quality winner exists. This update adds a training plan only; no account was accessed, data uploaded or compute run.

## Phase 2C: advisory integration only after a win

Use `crates/eval/scripts/decision_poc_v2/` for new adapters, preparation, tests, model locks and reports. Reuse the existing `please-bench-jsonl/v1` runner, native contextual normalizer, immutable saved-run verification and v2 `group_baselines`. Keep the phase-1 directory and runs intact. No shipping dependency changes are needed for 2A or 2B.

The bench context has task plus allow/deny permissions; the shipping review context additionally carries explicit boundaries and relevant/known/unavailable scope. Before integration, test a lossless mapping against `crates/core/src/context.rs` and `crates/judge/src/ml_review.rs`. Passing the simplified bench is necessary, not sufficient, for that richer contract.

Initially emit advisory contextual observations. A generic NLI model does not extract validated evidence spans: leave evidence empty rather than inventing spans or treating attention as proof. Boundary IDs and exact UTF-8 evidence mapping require a separate tested design before producing a supported-violation review result. Missing relevant scope, model failure or cap exhaustion must remain indeterminate. Existing `MayRelease` authority must not be granted automatically.

Fixed token, hypothesis and request-count caps bound this experimental transformer's resource use; they do not prove linear-time analysis for arbitrary documents. Before shipping, document the optional engine justification, bounded work and long-document policy under the constitution. Do not route neural dependencies into core or the default build.

## Implementation sequence and completion criteria

1. **Diagnostic commit:** immutable raw-score audit, three recipe configs, pinned assets and adapter parity tests. Done when saturation, label mapping, invalid scores and overflow are covered before behavior changes.
2. **Data commit:** authored development pack, separate calibration pack, label rubric, controls and split/exposure checks. Done when label provenance and grouping are reviewable without model outputs.
3. **Benchmark commit:** verified CPU/GPU runs, source-stratified quality/coverage tables, whole-decision timings, calibration selection and explicit screening-gate results. Stop or proceed based on those results.
4. **Independent evaluation:** freeze the finalist and evaluate fresh reviewed holdout once. Publish failures and confidence limits. If collection is unavailable, deliver a development-only result without claiming completion of this gate.
5. **Conditional follow-up:** supervised training if generic recipes fail; advisory shipping integration only after evidence supports it. Each creates its own scope and frozen candidate.

Planning work in this document changes no detection behavior. Implementation must follow the repository's test-first detection workflow, property tests for bounds and malformed inputs, official-model parity checks, saved-run integrity checks, and optional-dependency/WASM guards if shipping crates are eventually touched. Core invariants follow the [constitution](../../.specify/memory/constitution.md); the experiment contract follows [BENCH.md](../../crates/eval/BENCH.md).
