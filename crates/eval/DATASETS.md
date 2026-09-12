# Fresh dataset evaluation

Use published dataset labels to prepare new benchmark samples without collecting live-site traffic
or asking an application owner to relabel every row. Preserve the distinction: these are upstream
benchmark labels, not owner judgments about an application's permissions.

## September 11 frozen set

**Evaluation completed:** see the [600-case results](../../docs/research/dataset-evaluation-2026-09-11.md)
for structural and structural-plus-local-ML decisions, source breakdowns, and coverage gaps.
These cases are now exposed for future tuning. The immutable freeze records preparation-time status;
the separate local `evaluation-01/exposure.json` records their subsequent use.

The ignored `.cache/dataset-evaluation-20260911/frozen-01/` package contains **600 direct prompts**:

| Upstream source | Injection | Benign |
| --- | ---: | ---: |
| Gandalf-Ignore | 100 | 0 |
| safe-guard-PI | 100 | 100 |
| jayavibhav-PI | 100 | 100 |
| OR-Bench | 0 | 100 |

The source is [Necent/llm-jailbreak-prompt-injection-dataset](https://huggingface.co/datasets/Necent/llm-jailbreak-prompt-injection-dataset)
at the repository's already-pinned revision `4edfb5aeaafe58c9bf489a478a42188f239d7c1e`.
`prompt_adversarial` supplies the injection label; every selected row has `prompt_harmful = 0`.
The dataset documents these as separate labels. This tests harmless attacks against clean controls,
not harmful-content detection. The aggregate's integration-code license does not replace its
underlying sources' licenses; raw dataset text stays local and ignored.

Freeze SHA-256, retained separately here:

```text
b639b914754726b6211fd8ef064b12355ebeb792fe7bf050327638d9eb70c8e4
```

No detector, classifier, or judge was run on the selected inputs during preparation. Payloads were
not printed for inspection. Labels were inherited programmatically and were not owner-adjudicated.
The public preparation script and tests contain no sampled prompt text.

## Selection and what “fresh” means

The plan indexes 72,122 exact input hashes from existing committed manifests, authored fixtures,
cached prior corpus inputs, and historical SHART candidates. Where prior text is available, it also
indexes 72,039 hashes after Unicode NFKC normalization, case folding, and whitespace collapsing.
Legacy exports containing literal newlines in JSON strings are parsed without dropping those rows.
The plan saves every input inventory file's digest and the exact exclusion sets.

The pinned query rejects previously used exact bytes and conflicting adversarial labels for the
same bytes, then selects candidates by ascending SHA-256 within source/label strata. It requests
up to four times the final quota so normalized duplicates can be removed locally. The freeze rejects
normalized exposure, cross-source normalized duplicates, and conflicting normalized labels. It
requires the full declared quota in each stratum; shortages fail rather than silently changing
the sample. No selection uses scanner scores or outcomes.

This is a **within-source holdout from indexed local evaluations**. It does not prove that a model
has never seen the rows in training, that all historical experiments were indexed, or that semantic
paraphrases and attack families are independent. Normalization does not rewrite the bytes scanned.
Do not call it an independent source holdout or a deployment acceptance test.

The pinned aggregate has no unused InjecAgent, LLMail-Inject, BIPIA, or ToolEmu rows after excluding
prior evaluations. Those existing rows remain development/regression data. This new set therefore
uses the explicit caller policy `untrusted_user_input` with role `user`. It supplies **no fresh
tool-response or security-reference coverage**. SPML/TensorTrust are not sampled; their serialization
artifacts are described in [the corpus slice definitions](corpus/slices.toml).

Benchmark labels also do not establish whether an export destination is authorized in a particular
application. Those experiments still need task/permission context. Report results by source and
label; the equal quotas are a testing choice, not estimated deployment prevalence.

## Reproduce preparation

The script uses Python's standard library for preparation. Only the explicit `hf datasets sql`
command accesses the network, using the existing account's dataset access. Output directories must
be new. Run from the repository root:

```bash
python3 -B crates/eval/scripts/prepare_dataset_holdout.py plan \
  --cache /home/jg/.cache/please-eval \
  --out .cache/dataset-evaluation-20260911/plan-02

hf datasets sql "$(cat .cache/dataset-evaluation-20260911/plan-02/select.sql)" \
  --format json > .cache/dataset-evaluation-20260911/plan-02/candidates.json

python3 -B crates/eval/scripts/prepare_dataset_holdout.py freeze \
  --plan .cache/dataset-evaluation-20260911/plan-02 \
  --rows .cache/dataset-evaluation-20260911/plan-02/candidates.json \
  --out .cache/dataset-evaluation-20260911/frozen-02
```

Replace the cache path with your existing evaluation cache. A different exposure history can
produce a different sample; the local plan is the reproduction record. The script does not currently
automatically index separately prepared dataset packs: when a pack is used, add its `captures.jsonl`
hashes to the exposure history before planning another fresh set. Re-running these commands with the
same history reproduces selection; it does not create a second independent set.

The frozen package contains replay-compatible `captures.jsonl`, source/label metadata in
`provenance.jsonl`, exact `inputs/*.bin`, the selection plan, and `freeze.json`. The freeze pins all
package files, the plan, the candidate export, and the preparation script. Use its own checker;
`capture check` belongs to the separate owner-reviewed live-capture format.

```bash
python3 -B crates/eval/scripts/prepare_dataset_holdout.py check \
  --dir .cache/dataset-evaluation-20260911/frozen-01 \
  --sha256 b639b914754726b6211fd8ef064b12355ebeb792fe7bf050327638d9eb70c8e4
```

Fix candidate code/configuration before inspecting holdout outcomes. The existing
[replay command](REPLAY.md) can consume `captures.jsonl` once real baseline outputs exist; its report
groups by caller source/role, so use `provenance.jsonl` to retain the upstream-source breakdown.
Do not fabricate baseline results from labels. After inspecting results, treat the cases as exposed
for subsequent tuning. The initial freeze establishes no detector accuracy claim.

Synthetic instrument checks run offline in CI:

```bash
python3 -B crates/eval/scripts/test_prepare_dataset_holdout.py
```

They cover exact-byte/label preservation, normalized exposure, missing strata, invalid labels/hashes,
changed plans, overwrite refusal, and tampered frozen payloads. They do not run model inference.
