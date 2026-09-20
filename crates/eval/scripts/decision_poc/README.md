# Lightweight decision-model proof of concept

A human-directed, Codex-authored development experiment. The shipping Rust scanner, rules, dependencies and enforcement policy are unchanged.

Read `docs/research/decision-model-poc-2026-09-16.md` first. GLiClass Small is fast locally, but these zero-shot decision recipes failed precision and contextual discrimination. This is a negative result for the tested model/recipe/operating point, not evidence against every small model. Do not deploy this adapter as a security gate.

## Artifacts

- `PLAN.md`: pre-inference scope, frozen thresholds, evaluation boundaries.
- `model.lock.json`: public upstream revision and exact runtime asset hashes.
- `requirements.lock.txt`: actual Python environment; PyTorch CUDA 12.6 build.
- `adapter.py`: one self-contained, offline `please-bench-jsonl/v1` process; complete raw scores in diagnostics, no model-written rationale.
- `test_adapter.py`: stdlib contract and randomized incomplete-score checks.
- `check_model.py`: real-weight parity with official GLiClass pipeline, overflow and injected class-marker refusal.
- `prepare.py`: validates and imports existing exposed packs into a cache-only 720-case pack, creates comparison manifests, freezes inputs and binaries.
- `baseline.py`: current shipping CLI structural and structural+ProtectAI runs, 630 identical artifact inputs per mode.
- `report.py`: verifies canonical bench results, recomputes baseline summaries from native verdicts, and generates paired source-stratified Markdown/HTML/JSON.

The Python tools locate the repository relative to their own location. Their local output root is `.cache/decision-poc-20260916`; environments, licensed corpus text and weights are ignored. They intentionally refuse overwriting an existing prepared suite/baseline. Preserve old runs and use fresh run labels for new measurements.

## Recorded comparison

Pack: all 600 exposed September 11 public cases plus the existing 30-group contextual pilot. 630 artifact cases, 90 contextual cases; source-stratified effectiveness only. Input IDs, hashes, labels and runtime identities are in the research manifest; public text is not redistributed.

Arms: structural enforcement/High; structural + ProtectAI (classifier threshold 700/1000, default impact, High action threshold); GLiClass binary softmax attack >=0.7; GLiClass decomposed maximum sigmoid signal >=0.7. Contextual decomposition uses reference/conflict/authorized scores at 0.7 with that precedence; otherwise abstains. The blind contextual ablation maps candidate-only binary output to conflict/non-instruction and cannot predict aligned instruction. No labels or context IDs reach the candidate model.

Bench runs execute 4 systems x 720 cases = 2,880 rows per device. Unsupported surface/system combinations are explicitly recorded, not actual inference calls. Interpret only supported surfaces. The first GPU run failed during warmup due to missing explicit output class count; `run-cuda0-v2` is the corrected run, with identical questions and thresholds. No detector decisions were produced by that failed integration attempt.

All candidate inference is local and configured offline. This is declared offline, not an OS-enforced network sandbox. Cold-start imports/asset verification are excluded from per-call timings; CLI baseline totals include load. CPU and GPU are measured separately, without simultaneous inference. The Python classifier uses float32, four CPU threads and batch size one.

## Reproduction on Ubuntu / WSL

Requires the existing licensed `.cache/dataset-evaluation-20260911/frozen-01` inputs and pinned ProtectAI cache; missing assets fail explicitly. A fresh clone alone cannot reproduce private cached public-corpus text. The freeze source is described in `crates/eval/DATASETS.md` and `docs/research/dataset-evaluation-2026-09-11.md`.

From the repository root, on a fresh experiment cache:

```bash
uv venv .cache/decision-poc-venv
uv pip install --python .cache/decision-poc-venv/bin/python   -r crates/eval/scripts/decision_poc/requirements.lock.txt --torch-backend cu126
cargo build --release --locked --offline -p please-cli --no-default-features --features ml-candle
cargo build --release --locked --offline --manifest-path crates/eval/Cargo.toml
python3 crates/eval/scripts/decision_poc/fetch_model.py
python3 crates/eval/scripts/decision_poc/prepare.py
python3 crates/eval/scripts/decision_poc/baseline.py
crates/eval/target/release/please-eval bench run   --experiment .cache/decision-poc-20260916/experiment-cuda0.json   --out .cache/decision-poc-20260916/run-cuda0-v2
crates/eval/target/release/please-eval bench run   --experiment .cache/decision-poc-20260916/experiment-cpu.json   --out .cache/decision-poc-20260916/run-cpu
.cache/decision-poc-venv/bin/python crates/eval/scripts/decision_poc/check_model.py
python3 crates/eval/scripts/decision_poc/report.py
```

GPU runs require CUDA; do not silently substitute CPU. To reproduce only a subset, create a new named plan and report that subset explicitly. The combined report intentionally requires both completed device runs.

Reopen existing evidence without inference:

```bash
python3 crates/eval/scripts/decision_poc/report.py
crates/eval/target/release/please-eval bench view --run .cache/decision-poc-20260916/run-cuda0-v2
```

Checks:

```bash
(cd crates/eval/scripts/decision_poc && python3 -m unittest -v test_adapter.py)
.cache/decision-poc-venv/bin/python crates/eval/scripts/decision_poc/check_model.py
```

## Next bounded comparison

Keep this failed arm. Add an entailment-oriented model as a separately declared candidate, ask whether evidence supports each boundary claim, and compare with an explicitly supervised/fine-tuned small classifier if needed. Owner-label the individual subquestions, not merely a document-level injection verdict. Include cases where the same instruction is authorized, forbidden, quoted, or underspecified, with task phrasing that does not reveal the answer template. Select thresholds on development data under a fixed false-positive budget; freeze model, wording and aggregation before an untouched holdout. Measure false releases separately from missed detections. Do not grant a model authority to clear structural findings based on this pilot.
