# Current reproduction guide — September 15, 2026

The latest detector measurement is the
[prefilter cost and fresh holdout follow-up](prefilter-cost-2026-09-15.md).
Its compacted literal gates preserve the earlier matching coverage; the older
experiments below retain their own frozen detector identities.

Use this guide for reproducing the historical email experiment and the accepted
role-marker follow-up. The [September 14 email report](detection-improvement-2026-09-14.md)
and its machine record are retained unchanged as historical evidence. Its command
that builds the current checkout no longer reproduces that detector: the email
rules were withdrawn, and the role-marker correction is now enabled.

## Historical email candidate: use the frozen executable

The historical **510/1,054 InjecAgent** result belongs to the withdrawn email
candidate, ruleset digest `98eb13cabaeedf28`. The current detector produces
**442/1,054** on those same inputs. Replaying the historical binary measures that
old detector; it does not re-enable its rules in the current checkout.

These commands require the locally retained evidence under
`.cache/detection-improvement-20260914/`, including the executable and licensed
frozen corpus. They do not download or reconstruct missing evidence. Run from
the repository root, and use an unused run label or cache directory on each replay.

First verify the fixed input, frozen executable, and its freeze manifest:

```bash
sha256sum --check <<'CHECKSUMS'
f73131d13f3c0e479e4d71c110819770b4d56a5d2c8352902a076f32413f7b30  .cache/detection-improvement-20260914/candidate-freeze/frozen-corpus
48653f39a26bdaf03b8d46a57b7d9006433fdc3622eb35b3413d834e71c88009  .cache/detection-improvement-20260914/candidate-freeze/freeze.json
38467834f5490d6823e5525b5c71f380c6b8c6d019a2072ced1c3ea2a295ca9f  .cache/detection-improvement-20260914/development.json
CHECKSUMS
```

Only after all three checks pass, run the **frozen email candidate**:

```bash
PLEASE_EVAL_CACHE="$PWD/.cache/historical-email-reproduction" \
  .cache/detection-improvement-20260914/candidate-freeze/frozen-corpus run \
  .cache/detection-improvement-20260914/development.json \
  38467834f5490d6823e5525b5c71f380c6b8c6d019a2072ced1c3ea2a295ca9f \
  frozen-email-candidate-01 high pos_injecagent pos_llmail neg_orbench neg_clean \
  neg_nonadversarial neg_multilingual fix_benign gen_matched_negative repo_prose
```

Expected primary detections are InjecAgent **510/1,054**, LLMail
**11,263/27,963**, and OR-Bench false positives **0/3,000**. LLMail retains
**154 distinct incomplete rows**. The three additional incomplete rows and
12,239 LLMail detections belong to the later role-marker correction.

To inspect and verify the saved run, build the current reporting executable:

```bash
cargo build --release --locked --offline --manifest-path crates/eval/Cargo.toml \
  --bin please-eval
PLEASE_EVAL_CACHE="$PWD/.cache/historical-email-reproduction" \
  crates/eval/target/release/please-eval report \
  --run frozen-email-candidate-01 --format json
```

This report command reads saved results and does not scan using the current
detector. Confirm `integrity.status` is `complete` and `ruleset_digest` is
`98eb13cabaeedf28`; a successful report command alone does not prove completeness
or a passing regression gate. Saved native rows should exactly match the nine
slices in `.cache/detection-improvement-20260914/eval-cache/results/final-candidate-01/`.

The original report, machine record, candidate freeze, and native results are
preserved. The current reproduction was checked against all nine historical
native result files, not just the three displayed totals. Source rebuilding is
unnecessary when replaying this pinned executable; a build of today's checkout
is not a substitute for a missing historical binary.

## Role-marker evidence: verify native runs before counting

The [accepted follow-up](role-marker-prefilter-follow-up-2026-09-14.md) describes
the role-marker correction before the subsequent
[all-rule matching audit](matching-consistency-2026-09-15.md). Its auditor invokes the native saved-run verifier,
requires complete runs, verifies the bytes it reads against each completion
record, binds row IDs and selection to checksum-verified frozen inputs, and
recomputes all counts and differences. A supplied `summary.json` that disagrees
is rejected before any report is written. It also rechecks historical LLMail
equality and preserved artifact hashes, and derives timing medians from recorded
samples. Timing samples themselves remain recorded measurements, not independently
remeasured latency.

After building `please-eval` as above:

```bash
python3 crates/eval/scripts/detection_experiment/audit_role_marker_follow_up.py \
  .cache/role-marker-follow-up-20260915 /tmp/role-marker-verified-new.json \
  --evaluator crates/eval/target/release/please-eval
```

Use a new output filename. This verifies evidence consistency; it is not proof
of authenticity against someone able to replace all inputs, manifests, programs,
and results together. Corpus labels retain their documented authorship and
development-exposure limitations.

## Clean-baseline patch check and audit regressions

The [preserved patch](role-marker-prefilter-candidate.patch) now includes the
rule change, regression tests, and `data/role_marker_controls.jsonl`. The clean
baseline is commit `90f56768e40de330bb0dbb5e598984d650de1260`.

```bash
bash crates/eval/scripts/detection_experiment/check_role_marker_patch.sh
cargo test --manifest-path crates/eval/Cargo.toml --locked --offline \
  --test role_marker_audit
python3 crates/eval/scripts/detection_experiment/test_audit_role_marker_follow_up.py
```

The patch check exports that commit into a new temporary directory, verifies the
fixture was absent, applies the patch, compiles/runs eight focused tests, and
checks the installed fixture bytes. It does not copy untracked workspace files
into the baseline. It requires cached Rust dependencies for the offline build.

The Rust regression creates small complete runs through the real evaluator and
checks corrupted summaries, invented differences, changed native bytes, missing
completion records, unfinished runs, input identity mismatches, and changed
pipeline metadata. It needs Python 3 but no private corpus. The additional Python
CLI regression uses retained local evidence to reproduce the exact review case
(12,239 changed to 27,963); it skips explicitly if those local artifacts are absent.
