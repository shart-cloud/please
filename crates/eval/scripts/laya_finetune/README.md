# Laya prompt-injection fine-tuning on Colab Pro

This workflow full-fine-tunes `convaiinnovations/laya` as a calibrated binary prompt-injection
decision model. It is designed to run entirely on a Colab GPU with ephemeral `/content` storage;
checkpoints and final artifacts go to a **private** Hugging Face model repository.

The existing manifests under `crates/eval/manifests/` remain a frozen benchmark. Every exact
content hash in those manifests is excluded from training and calibration. Raw dataset text is
also excluded from model uploads: only aggregate provenance, licenses, pinned revisions, and file
hashes are retained in `data_manifest.json`.

## Before opening Colab

1. Create a Hugging Face write token and add it to Colab Secrets as `HF_TOKEN`.
2. Add the destination model repo (for example `your-org/laya-prompt-injection`) as the Colab
   secret `HF_OUTPUT_REPO`. The script creates it as private if needed.
3. While logged into Hugging Face, accept any access prompts for the gated source datasets:
   `Necent/llm-jailbreak-prompt-injection-dataset` and
   `prodnull/prompt-injection-repo-dataset`.
4. Push this directory to the Git ref selected in the notebook, then open
   `colab_laya_finetune.ipynb` in Colab and choose a GPU runtime.

Colab Pro improves availability but does not promise a particular GPU. The defaults target a
single 16 GB-class GPU using fp16/bf16, encoder and head checkpointing, a micro-batch of 4, and
gradient accumulation. If the smoke run runs out of memory, set `MICRO_BATCH = 2` and
`GRAD_ACCUM = 16` in the notebook. These preserve the effective batch size.

## Dataset policy

Pinned inputs are declared in `datasets.json`.

| Dataset | Use | Reason |
|---|---|---|
| Necent aggregate | train + calibration | Broad source coverage; queried by hash so the million-row aggregate is not materialized locally |
| neuralchemy Prompt-injection-dataset | train; upstream validation/test reserved | Group-aware split and explicit provenance |
| 3nesdeniz agentic-prompt-injection-5k | train; upstream validation/test reserved | Scenario-isolated agentic attacks and paired hard negatives |
| prodnull prompt-injection-repo-dataset | train + deterministic calibration | Repository-file attacks and hard negatives |
| BrowseSafe-Bench | evaluation only | Long raw HTML needs a windowed browser-specific evaluator |
| ActBench | evaluation only | Contextual agent trajectories are not independent binary rows |
| NVIDIA Agentic IPI traces | evaluation/later adapter | Reinforcement-learning trajectories are not binary classifier examples |

The builder removes exact benchmark overlaps, Unicode/whitespace-normalized duplicates, and every
normalized-text group with conflicting labels. It also excludes known serialization artifacts and
holds publisher validation/test splits outside optimization and temperature fitting. Public data
can still contain semantic near-duplicates or label errors, so final promotion should depend on the
project's frozen benchmark and an owner-adjudicated production sample.

## What the notebook runs

The thin notebook invokes these two versioned scripts:

```bash
python crates/eval/scripts/laya_finetune/prepare_data.py \
  --repo-root /content/please \
  --out /content/laya-data

python crates/eval/scripts/laya_finetune/train_laya.py \
  --data /content/laya-data \
  --output /content/laya-output \
  --hf-output-repo your-org/laya-prompt-injection
```

Training follows Laya's published recipe: full encoder/head tuning, RLCD with proper-scoring reward,
and cross-entropy guidance. Calibration uses a separate split and fits only the binary-choice
temperature. Each epoch writes `checkpoint_latest/` with weights plus optimizer, scheduler, scaler,
and random state, then uploads it privately. Rerun with `--resume` after a disconnect.

The notebook first runs a small `--limit-train 512 --epochs 1 --no-upload` smoke test. Delete
`/content/laya-smoke` before repeating that cell, or choose another output path.

## Local checks (no model or dataset download)

```bash
python -m unittest discover -s crates/eval/scripts/laya_finetune -v
python -m py_compile crates/eval/scripts/laya_finetune/*.py
python -m json.tool crates/eval/scripts/laya_finetune/colab_laya_finetune.ipynb >/dev/null
```

Do not commit `/content/laya-data`, raw prompts, tokens, or complete training checkpoints to this
repository. Dataset terms remain those of each pinned upstream source; the model card should retain
the generated source and license manifest.
