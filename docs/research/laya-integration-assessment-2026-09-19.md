# Laya integration assessment — 2026-09-19

Recommendation: add Laya first as an isolated local benchmark adapter, then consider
an explicitly selected local advisory backend if reviewed evaluations support it.
This is a source/configuration review and implementation proposal, not a completed
integration or a model-quality measurement. No weights, packages, inference or API
credits were used. Existing uncommitted work was preserved.

Reviewed upstream commit: 6a5819129eb220570792e417e49723d697efd76f; package metadata: 0.3.3.
Source hashes and pinned model configuration identities are in
.cache/laya-review-20260919/sources.json.

## Fit

Laya accepts state plus typed questions and returns choice distributions, scores
or boolean probabilities. That makes its request interface close to Jev's.
Its Python runtime uses Torch/Transformers and custom decision heads; inference
can run locally. It is a plausible trainable local decision-model candidate.
See [runtime](https://github.com/NandhaKishorM/laya/blob/6a5819129eb220570792e417e49723d697efd76f/laya/agent.py) and
[package dependencies](https://github.com/NandhaKishorM/laya/blob/6a5819129eb220570792e417e49723d697efd76f/pyproject.toml).

This is distinct from merely rerunning the earlier ModernBERT NLI checkpoint:
Laya adds typed decision heads and task-oriented training. Sharing a backbone
does not establish equivalent behavior or improved Please performance.

The upstream guard preset mixes injection, jailbreak, sensitive information,
harm severity and topic. Please should define its own caller-owned questions
and keep artifact detection separate from contextual relation.
See [presets](https://github.com/NandhaKishorM/laya/blob/6a5819129eb220570792e417e49723d697efd76f/laya/presets.py).

## Concrete compatibility findings

1. **Silent shortening is the main blocker.** build_sequence caps each option's
   text at 48 tokens, can shorten all options further to fit the head budget,
   trims question instructions and then slices the serialized state. It also
   replaces literal mask-token strings with spaces. Please must preflight every
   component using the exact pinned tokenizer and reject any shortening or marker
   rewriting, before model execution. A byte limit alone is insufficient. Shorter
   prompts are separate frozen recipes, not unnoticed rewrites of the Jev recipe.
2. **Confidence has different semantics.** Choice confidence is normalized
   inverse entropy, not a calibrated correctness probability; the boolean path
   uses the winning binary probability. Retain native values separately and
   calibrate Please's acceptance gates on independently reviewed calibration.
   Do not transplant Jev's confidence threshold.
3. **Native output needs its own adapter.** Choice answers contain an additional
   action object, and direct Agent output identifies itself generically as
   laya-rl-agent. Preserve the full native response, but record the actual pinned
   checkpoint, tokenizer, source, recipe, device and temperature configuration.
   Never treat action probability as release authority or pretend this is Jev.
4. **Offline loading needs preparation.** Loading can download from the Hub,
   fall back to another encoder/tokenizer location, modify tokenizer config,
   and fall back from GPU to CPU. Provision all pinned files ahead of time;
   hash any compatibility-adjusted copy as a derived artifact. Run the benchmark
   offline, isolate protocol stdout from library messages, and record or reject
   device fallback so timing is not mislabelled.

Sources: [sequence builder and confidence](https://github.com/NandhaKishorM/laya/blob/6a5819129eb220570792e417e49723d697efd76f/laya/common.py),
[loader and output construction](https://github.com/NandhaKishorM/laya/blob/6a5819129eb220570792e417e49723d697efd76f/laya/agent.py).

## Checkpoints to compare explicitly

| Checkpoint | Pinned configuration | Role |
|---|---|---|
| English laya | max_len 512, head_max_len 192 | English base control |
| laya-typed-decisions | max_len 1024, head_max_len 256 | Task-tuned challenger; transfer to Please is unproven |
| laya-multilingual | max_len 1024, head_max_len 256 | Later separate multilingual experiment |

These are total sequence/head limits, not candidate-only allowances. Actual state
room depends on encoded questions and options. Do not raise limits and claim
unchanged checkpoint behavior without evaluating that variant.

The typed checkpoint's configuration contains both per-type temperatures and
per-option-bucket overrides. Agent uses bucket overrides first; record the
effective value, not just the per-type array. All three inspected model cards
declare Apache-2.0. Retain upstream license/attribution when distributing code
or model derivatives.

Use explicit checkpoint selection initially. The router's language/model
selection is separate from research H's caller-selected analysis/action-review
mode. Candidate claims cannot select authority or intended workflow.
See [router](https://github.com/NandhaKishorM/laya/blob/6a5819129eb220570792e417e49723d697efd76f/laya/router.py).

## Proposed implementation sequence

### 1. Bounded offline adapter and contracts

Add proposed files under crates/eval/scripts/decision_laya/:
adapter.py, recipes.json, asset-lock.json, test_adapter.py and README.md.
Reuse the please-bench-jsonl/v1 subprocess handshake and case/result envelopes
from decision_poc_v2, with one persistent model process per pinned arm. No new
shipping Cargo dependency or core modification is necessary for this stage.

Declare separate artifact and contextual systems. Initially support one surface
at a time. Freeze questions, label order, input rendering, token budgets,
temperature configuration, normalization and model identity before runs.

Record native probabilities, choice, entropy confidence, action output, input
identity, token counts, actual device/precision, load time, warm inference time,
whole-decision time, RSS/VRAM and explicit failure reasons. Empty evidence and
no review authority. No network fallback. Preserve failed/over-cap cases in
denominators. Retain model processing token counts as such, not API billing.

Contract tests must cover candidate bytes/identity, unknown/missing context,
instruction/option/state limits separately, reserved markers, non-finite scores,
distribution sums, choice consistency, timeouts, device fallback, native parity
and protocol output isolation. Avoid treating the library's advertised minimum
dependencies as a tested runtime lock; pin a verified compatible environment.

### 2. Small frozen comparison, then reviewed evaluation

First check fit/coverage and numerical parity against the pinned reference.
Compare English base and typed-decisions explicitly on a small predeclared
development slice. Reuse existing Jev captures where input, recipe and case
identities match; label them historical, not contemporaneous.

For contextual advice, compare four-way questions with a separately versioned
caller-directed recipe only after its context mapping is defined. Include
candidate-only, context-only, quotation/redirection, permission mismatch and
label-order controls. Do not repurpose the generic guard preset as the contextual
truth definition.

The September 18 framework runs and September 19 paired audit are newer evidence
than this task's initial handoff. There is now a 6,000-public/600-contextual
comparison and a paired-error analysis. Use the native framework and matching
case identities to test whether Laya recovers Jev misses without adding excessive
benign false alarms. Keep artifact and contextual figures separate. Existing
packs and the 24-case review packet are exposed development material.

Independent label review, separate calibration and untouched workflow families
remain required before promotion. Freeze the acceptable false-positive budget,
coverage/recall gates and resource limits before evaluation, rather than choosing
them after inspecting Laya's outputs.

### 3. Optional personal-use integration

If the evidence supports it, introduce an explicit local backend selector in
the CLI/TUI, backed by a persistent local worker. Keep presets reusable and
requests explicit. A provider-neutral, versioned advice record should carry
backend identity and native score semantics. Continue reading historical Jev v1
files; do not force Laya responses through the Jev-only parser.

A local-to-Jev escalation policy is a later opt-in caller choice. Low confidence,
an input limit or backend failure must remain indeterminate unless the user has
explicitly configured remote assessment. Do not automatically combine detectors
with OR or AND without evaluating the false-positive and coverage tradeoffs.

### 4. Rust or fine-tuning only after evidence

The existing GLiNER2 Candle implementation is not a Laya loader. Native Laya needs
its encoder, extra TransformerEncoder layers, type embeddings, scorer, action head,
exact token packing and temperature behavior implemented and compared numerically
with the reference. Start with Python to evaluate value before committing to a port.

Fine-tuning is a plausible later use of reviewed caller-task data. Do not turn the
same authored review packet into both training and holdout data.

## What the advertised numbers establish

Upstream explicitly states its Jev comparisons use third-party measurements with
different prompts/sample sizes. Its strongest typed-decisions result belongs to a
checkpoint fine-tuned on that benchmark's training split; it does not establish
Please-specific injection or analysis/redirection performance. The advertised
single-question speed is measured on a T4 GPU, not this workstation.
See [benchmark report](https://github.com/NandhaKishorM/laya/blob/6a5819129eb220570792e417e49723d697efd76f/BENCHMARKS.md).

No accuracy, latency, calibration improvement or API-cost savings for Please has
been measured in this review.
