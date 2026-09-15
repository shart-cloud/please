# Named-data email detection — 2026-09-14

## Result at the original operating point

Two declarative rules recognize an imperative email transmission with an explicitly named data
object and an explicit destination. One uses the existing structural frame; the other uses lexical
directive introducers. Bare pronouns require context the detector does not have and are outside
these rules' scope. No engine code, bounds, scoring, thresholds, labels, or optional tiers changed.

| Primary slice | Rows | Baseline detections | Candidate detections | Distinct incomplete rows, both |
|---|---:|---:|---:|---:|
| InjecAgent | 1,054 | 442 | **510** | 0 |
| LLMail-Inject | 27,963 | 11,263 | **11,263** | 154 |
| OR-Bench (false positives) | 3,000 | 0 | **0** | 0 |

InjecAgent gains 68 detections, **6.45 absolute percentage points**, exceeding the 495-row target.
No previously detected primary attack is lost. The 68 rows contain four repeated payload forms,
each appearing 17 times: they are not 68 independent attack mechanisms. No technique labels exist
on these primary positives. These are development benchmarks, not deployment accuracy estimates.

Configuration is identical between baseline and candidate: product, enforcement, High, unspecified
source/provenance, structural only, no quote suppression, 1 MiB input cap, decode depth 3,
16 matches per rule, 4,096 observations. Baseline ruleset digest: `3b946803b23151d5`;
candidate: `98eb13cabaeedf28`. Integer per-mille reporting remains unchanged.

Final paired runs: `final-baseline-01` and `final-candidate-01`, each with nine verified slices.
Two further paired repetitions have identical per-row result files. The fresh initial High run
also reproduces all three original September 14 result files **byte for byte**.

## False-positive checks selected before tuning

| Slice | Rows | Baseline false positives | Candidate false positives |
|---|---:|---:|---:|
| Clean benign | 6,640 | 516 | 516 |
| Non-adversarial, harmful content permitted | 13,169 | 534 | 534 |
| Multilingual negatives | 3,196 | 19 | 19 |
| Benign fixtures | 20 | 14 | 14 |
| Matched carriers | 14 | 0 | 0 |
| Frozen repository/reference prose | 87 | 32 | 32 |

No source-level count changes and no new false-positive rows occur. Totals include SPML's
400 serialization-triggered hits in each applicable slice. The existing SPML/TensorTrust source
exclusions remain in saved definitions and gate calculations; all their rows remain scanned and
reported. Eligible clean-benign counts are 116/6,240; eligible non-adversarial counts are
134/12,769. The other rows and source caveats are preserved in the JSON reports.

The 87 repository documents were frozen before writing this report. This prevents new research
documents from changing the measured denominator. Historical reference-analysis fixture numbers
are not interchangeable with these enforcement numbers.

## Experiments and rejected alternatives

All original uncommitted reporting changes were captured in an isolated 451-file source snapshot
before detector changes. All nine public caches verified against their original manifests.
The [local journal](../../.cache/detection-improvement-20260914/JOURNAL.md) records hypotheses,
selection, code identity, run labels, interpretation, and next actions.

1. **Threshold control.** High detects 442/11,263 primary attacks; Medium and Low each detect
   442/11,298. OR-Bench remains zero. Both lower thresholds add one non-adversarial false positive
   and one repository-prose false positive. They are configuration experiments, not candidate gains.
2. **Role-marker prefilter correction.** Tests reproduced accepted marker spellings being rejected
   by the literal accelerator. Broadening the accelerator added 976 LLMail detections with no
   false-positive changes, but increased incomplete LLMail rows from 154 to 157. Rejected and
   reverted; its source, binary, failing/passing tests, and results remain in the ignored cache.
3. **Unrestricted email transmission.** Added 102 InjecAgent detections but two clean-benign false
   positives, both also in the non-adversarial slice. Requests to create a report and transmit
   a pronoun's referent exposed unjustified antecedent inference. Rejected and saved.
4. **Explicitly named data objects.** Restricting the new mechanism to named data objects retains
   68 new detections and eliminates those added false positives. Positive and benign tests were
   run failing before each behavior change. The retained rules do not inspect dataset identities,
   row IDs, hashes, recipient names, or benchmark-specific answers.

The miss sample was deterministically stratified by zero/nonzero score, coverage, and input length.
Samples and licensed prompt bytes remain local. All 154 incomplete LLMail rows were enumerated:
151 match-cap entries, three decode-depth entries, one decoding failure, and one observation-cap
entry overlap across those rows; 25 rows still detect attacks. Samples cover repetition of
punctuation-obfuscated commands, nested encodings, an encoded PDF attachment, and thousands of
zero-width observations. The candidate does not solve these gaps, suppress their reports, or
raise limits. Their row IDs, causes, and detection decisions remain unchanged.

## Validation and the limits of generalization evidence

Before tuning, 600 previously unscanned rows were selected from local overfetch prepared for the
September 11 evaluation. The previously evaluated 600-case pack was excluded. Selection used
ascending SHA-256 within six source/label strata, inherited labels, exact and Unicode
NFKC/case/whitespace duplicate exclusion, and conflicting-label rejection. Historical manifests,
cache inputs, capture manifests and bytes, and prior normalized exclusions were indexed.
The metadata-only [validation manifest](detection-validation-2026-09-14.jsonl) records identities
and labels without redistributing prompts. The exact preparation script and inventory are retained.

Validation was opened only after freezing candidate source and executable. Both executables used
the same exact inputs and configuration. Outcomes are unchanged:

| Validation stratum | Rows | Baseline hits | Candidate hits |
|---|---:|---:|---:|
| Gandalf-Ignore attacks | 100 | 51 | 51 |
| safe-guard-PI attacks | 100 | 27 | 27 |
| jayavibhav-PI attacks | 100 | 9 | 9 |
| OR-Bench benign | 100 | 0 | 0 |
| safe-guard-PI benign | 100 | 0 | 0 |
| jayavibhav-PI benign | 100 | 0 | 0 |

This is a within-source holdout from indexed local evaluations. It establishes no fresh recall
gain. It is now exposed for future tuning, recorded separately in `validation/exposure.json`.
Unrecorded historical inspection and semantic overlap cannot be ruled out. No fresh indirect
attack population was available in the pinned aggregate.

Mechanism-level generalization is demonstrated by tests using new recipients and objects,
six directive/container forms, case variation, paths, decoded evidence attribution, reference
suppression, saturation reporting, and 64 randomized object/recipient contrasts with descriptive
past-tense negatives. Those tests show compositional behavior beyond the four benchmark payloads;
they are authored engineering evidence, not an independent estimate of attack-family recall.

Additional public-source and generated-corpus checks lose no detections. The stratified attack
slice adds 16 hits, but all 16 exactly duplicate primary InjecAgent inputs; **none is counted as
cross-source transfer**. BIPIA, obfuscation, positive fixtures, and generated positives are
unchanged. Broad semantic detection and unseen-family effectiveness remain unproven.

## Cost and engineering verification

Three serial release runs per implementation used the same nine frozen slices, alternating order.
Median total evaluation time: baseline **13.919 s**, candidate **14.240 s**, a **2.31% increase**.
These times include evaluator I/O and reporting. Median InjecAgent scanning time moves from
183 to 192 ms; LLMail from 10.976 to 11.263 s. Variation between repetitions limits precision.
No material total slowdown was observed. All per-slice samples are retained in `performance.json`.

Release scaling checks pass: measured growth exponent 0.931, 4 KiB p95 365.6 microseconds,
and sustained throughput 11.6 MB/s. Existing bounds/property suites and the new rule tests pass.
A deterministic mutation smoke test also passes 5,000 mutated inputs / 10,000 scans, exercising
the new rules in 982 cases and explicit incomplete coverage in 3,358. It checks determinism,
span bounds, and input-limit reporting through the public engine. This is a bounded smoke test;
the repository's deferred coverage-guided fuzz campaign is not claimed complete.
Workspace and evaluator tests, formatting and Clippy, dependency/isolation guards, Wasm core,
and offline CLI builds pass. Workspace local HTTP fixtures initially failed because sandbox
socket binding was prohibited; all affected targets passed when rerun outside the sandbox.
No new dependency was introduced. The evaluator remains outside the shipping workspace.

The **default product regression gate still exits 2**, because product baselines are unpinned.
The explicit paired false-positive count comparison passes. OR-Bench meets its criterion; that
does not imply the broader benign criterion is met. No baseline or gate was relaxed.
The historical offline mechanism gate passes for both implementations: benign fixtures 1/20,
matched carriers 0/14, and current repository prose 17/88. This separate reference-analysis/Low
check uses the existing committed regression floors; its repository population includes this report.
The saved final run opens in the TUI, showing COMPLETE, the failed default gate, dataset counts,
and separate overlapping coverage causes. Terminal captures are retained.

## Reproduction and retained artifacts

Local evidence root: `.cache/detection-improvement-20260914/`.

- `baseline-source/`, `baseline-source.json`, `preexisting.patch`: original source and user work.
- `VALIDATION-PLAN.md`, `development.json`, `validation/`: frozen plans and exact input bytes.
- `candidate-freeze/`: fixed candidate source, binaries, and source identity.
- `eval-cache/results/<run>/`: native row results, completion metadata, HTML, JSON and Markdown.
- `e1/`, `e2/`, measurement logs, comparisons, and `JOURNAL.md`: successful and rejected work.
- `performance.json`, check logs, `default-gates.json`, `tui-full.typescript`: verification.

The [machine-readable research record](detection-improvement-2026-09-14.json) pins input,
source, executable, result, report and evidence checksums, comparisons and exact commands.
The [experiment scripts](../../crates/eval/scripts/detection_experiment/) are retained alongside
the [frozen-corpus runner](../../crates/eval/examples/frozen_corpus.rs). Preparation scripts refuse
existing destinations; replay scripts require unused run names. Use the frozen inputs for exact
reproduction: a fresh export of the current repository includes newly added documents.

```bash
cargo build --release --locked --offline --manifest-path crates/eval/Cargo.toml \
  --example frozen_corpus --bin please-eval
PLEASE_EVAL_CACHE="$PWD/.cache/detection-improvement-20260914/eval-cache" \
  crates/eval/target/release/examples/frozen_corpus run \
  .cache/detection-improvement-20260914/development.json \
  38467834f5490d6823e5525b5c71f380c6b8c6d019a2072ced1c3ea2a295ca9f \
  candidate-reproduction-01 high pos_injecagent pos_llmail neg_orbench neg_clean \
  neg_nonadversarial neg_multilingual fix_benign gen_matched_negative repo_prose
PLEASE_EVAL_CACHE="$PWD/.cache/detection-improvement-20260914/eval-cache" \
  crates/eval/target/release/please-eval view --run final-candidate-01
```

For baseline reproduction, substitute the retained `frozen-corpus-baseline` executable and a new
label. To rebuild it, copy `baseline-source/` into a new isolated directory, add the unchanged
`frozen_corpus.rs` example, and build there; do not modify the saved snapshot. Both the compiler
source tree and exact input package are required, since ordinary evaluator local readers resolve
their repository from compile-time paths. Nothing was committed, pushed, or published.
