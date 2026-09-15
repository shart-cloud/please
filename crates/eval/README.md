# `please-eval`

The evaluation harness. It produces the numbers behind every accuracy claim about PLEASE, and the
constitution constrains how — Principle IV: *reproducible from a committed manifest, reported per source
stratum, never as a bare aggregate, with the false-positive rate as a first-class gate and the known gaps
stated alongside the metrics.*

It is **outside the workspace** and carries its own lockfile. `cargo build --workspace` never sees it, so
its dependencies cannot reach `please-core`, whose 27-crate resolution `ci/check-dependencies.sh` pins.

## Quick start

```sh
# Offline — needs nothing but the repository
cargo run --manifest-path crates/eval/Cargo.toml -- generate            # build the span-labelled corpus
cargo run --manifest-path crates/eval/Cargo.toml -- run --offline --mode mechanism --run offline-baseline
cargo run --manifest-path crates/eval/Cargo.toml -- report --offline --run offline-baseline
cargo run --manifest-path crates/eval/Cargo.toml -- gate --offline --run offline-baseline  # exits 2 on failure

# The public corpus — needs the `hf` CLI and an approved dataset gate
hf auth whoami
cargo run --manifest-path crates/eval/Cargo.toml -- fetch
cargo run --manifest-path crates/eval/Cargo.toml -- manifest            # verify cache against manifests
cargo run --release --manifest-path crates/eval/Cargo.toml -- run --run public-product
cargo run --release --manifest-path crates/eval/Cargo.toml -- report --run public-product --out /tmp/report.md
```

Use `--release` for the public corpus. A debug build scans 60,000 rows at roughly a tenth of the speed;
the results are identical either way, which is the point of SC-011.

Use a fresh run label each time you repeat a measurement.

## Prompt-injection test bench

`please-eval bench` runs versioned artifact-detection and contextual-alignment case packs through
identity-bound in-process or external systems. It preserves native output, explicit failure/coverage
states, operating points, required strata, and paired-context changes without changing the shipping
scanner. The committed development pilot has 30 groups across three delivery vectors and is explicitly
not an independent holdout.

See [BENCH.md](BENCH.md) for the protocol and interpretation rules, and
[the feature quickstart](../../specs/007-prompt-injection-test-bench/quickstart.md) for a complete offline
run. The generic process boundary is covered in ordinary evaluator CI; real models, gated datasets,
remote reviewers, and third-party tools remain manual selections.

## Saved-run integrity

`run` records its fixed selection of slices before acquiring or scanning rows. It publishes each
complete result file atomically, records its row count and SHA-256, and marks the run complete only
after every selected slice has been saved. `run.json` also retains the pipeline configuration and the
resolved slice definitions, including exclusions and baselines. Reports use those saved definitions.

`report` and `gate` verify the entire recorded selection. Missing, unreadable, truncated, or modified
results make the run incomplete. Missing or invalid completion metadata makes it unverified, including
older runs that never recorded their expected slices. Unknown completeness is a failure requiring a
rerun; there is no legacy exception.

- Reports can still render available results, with `INCOMPLETE` or `UNVERIFIED` prominently displayed.
  JSON includes `integrity.status`, expected/verified slice counts, and per-slice issues. An unverified
  report's readable rows are for inspection; they are not established as complete.
- `gate` exits **2** for an incomplete or unverified run, even with `--allow-unpinned`.
- Existing run labels cannot be overwritten, extended, or resumed. Rerun the intended selection with
  a fresh `--run` label; previous artifacts remain available for inspection.
- `run --offline` selects local corpora. `report --offline` filters its metric tables, but integrity
  checks and the gate always cover every slice in the saved run. Reporting never fetches corpus data.
- Updating a mechanism baseline in `corpus/slices.toml` requires a fresh run to use that baseline.
  Product baselines remain unpinned, as before.

These checks establish saved-result completeness for the rows supplied to the scan. Verification of
the input corpus against its sampling manifest and detector coverage gaps within saved rows remain
separate checks. The checksums detect damaged artifacts; they do not authenticate a cache against
someone who can rewrite both its files and completion records.

## Shipping product measurements

`run` now defaults to product mode: the shared `please-scan::ScanSession`, enforcement profile, and
High action threshold. The quick-start gate above explicitly selects historical `--mode mechanism`.
Use a fresh `--run` label for product measurements. `run.json` records the policy, tiers, and scanned
ruleset identity; reports do not substitute the current ruleset. Product baselines start unpinned.

Enable `shipping-ml` and/or `shipping-judge` to use the same optional tiers as `plz`, with
`--ml-config`, `--ml-impact`, `--judge`, `--judge-allow-release`, and `--review-context`.
Profile and provenance are selected independently with `--profile` and `--provenance`.
The [migration notes](../../docs/research/policy-and-pipeline-2026-09-11.md) include complete examples.

## Replay actual lab captures

For a fresh published benchmark sample, see [dataset selection and freeze](DATASETS.md). The prepared
September 11 set contains 600 upstream-labeled direct prompts; it requires no live-site traffic.

Use [capture freeze/check](CAPTURE.md) to prepare fresh owner-labeled holdouts, reject known exposed
bytes and split leakage, and verify the collection before replay without inspecting detector outcomes.

The `replay` command compares local labeled captures with hash-matched saved results from an existing
scanner. It uses the shipped source policy at `High`, retains both sides' reasons and incomplete
outcomes, and reports disagreements without tuning rules. See [the replay format and workflow](REPLAY.md).
Actual capture files and baseline results must be supplied; the command does not acquire them or call
an external scanner.

## Phase-0 model feasibility

Historical model-feasibility experiments remain here, behind the eval crate's opt-in `ml` feature. The ordinary eval build and
the workspace dependency graph do not resolve Candle or `tokenizers`.

```sh
# The committed candidates and local cache state. No network, no Candle build.
cargo run --manifest-path crates/eval/Cargo.toml -- model list

# The only networked step. Uses the logged-in `hf` account or HF_TOKEN, downloads exact revisions,
# then validates every runtime asset against its committed byte length and SHA-256.
cargo run --manifest-path crates/eval/Cargo.toml -- model fetch

# Cache-only integrity and whole-bundle attribution (config + tokenizer + weights + pooling recipe).
cargo run --manifest-path crates/eval/Cargo.toml -- model check

# Real CPU inference. Reports load time, the median of ten warm runs, classifier probabilities, and
# MiniLM cosine similarities as JSON. It never downloads a missing model.
cargo run --release --manifest-path crates/eval/Cargo.toml --features ml -- model smoke
```

Individual ids can follow `fetch`, `check`, or `smoke`; run `model list` to see them. Model assets live
under `~/.cache/please-eval/models/` (or `PLEASE_EVAL_CACHE`) and are never committed. The three pinned
runtime bundles require 1.68 GiB, measured by `model check`: 549.6 MiB for ProtectAI, 1079.2 MiB for
Prompt Guard, and 87.1 MiB for MiniLM.

```sh
# SC-603: rank each generated row's injected payload against its sibling segments. Offline once the
# embedder is cached; writes the stratified report the spec quotes.
cargo run --release --manifest-path crates/eval/Cargo.toml --features ml -- \
  model outlier --out docs/research/embedding-outlier-results.md

# What the segmentation can reach, with no model and no `ml` feature at all.
cargo run --manifest-path crates/eval/Cargo.toml -- model outlier --dry-run

# The same measurement with prose cut into sentences rather than paragraphs.
cargo run --release --manifest-path crates/eval/Cargo.toml --features ml -- model outlier --sentences

# M2 and M7: is it a detector at all, and does it survive on text the generator never made?
cargo run --release --manifest-path crates/eval/Cargo.toml --features ml -- \
  model holdout --out docs/research/embedding-separation-results.md
```

`--sentences` is kept even though it loses — 51.9% against paragraph's 55.6% over the same rows. It is
the evidence that finer segmentation is not the fix the placement table appears to suggest, and a
comparison nobody can re-run is a comparison that has to be taken on trust.

`model outlier` exits 2 only on `abandon` — below 50% top-1, `document-map.md` §6's kill criterion.
`continue` (50–60%) exits 0 on purpose, for the same reason `gate` runs against a baseline rather than
against SC-003: a command that is red every day is a command people route around. It currently measures
**55.6% top-1, 80.3% top-3**, which is `continue`.

The segmentation it ranks against lives in `src/segment.rs` and is a **local subset** of
`document-map.md` §1.1, not a `DocumentMap` in `please-core` — that type is not implemented, and T006
needed sibling groups before the decision to build it could be taken. When the real one lands, delete
the module and re-run; the committed report names the version that produced it.

`model holdout` freezes the zero-false-positive threshold on the fourteen matched negatives and applies
it unchanged to the hand-written fixtures and to `docs/`+`specs/` — the held-out check
`document-map.md` §5.1 asks for. It measures **3.1%** against that memo's 25% floor: the score ranks
segments within a document but does not tell you whether the document has a payload in it. Both reports
are committed because §4 Phase 3 says the negative result is as publishable as the positive one.

`model smoke` is a feasibility instrument, not an accuracy gate. It proves that the exact architecture
loads and gives visible separation on a tiny sanity set. Thresholds are frozen only after the positive and
negative corpus strata have been measured; the command deliberately does not turn an assumed `0.7` into a
passing test.

## What is committed and what is not

| | where | why |
|---|---|---|
| slice definitions, carriers, payloads, positions | `corpus/` | reviewable inputs |
| model repository, revision, and per-asset digests | `corpus/models.toml` | the pin: which bytes a run was supposed to use |
| the generated corpus | `corpus/generated.jsonl` | generated text is ours to redistribute |
| prompt-injection bench development packs | `corpus/bench/` | first-party assets generated by `examples/generate_bench_pilot.rs`; exposed development evidence, not an independent holdout |
| row identity, labels, source, content hashes | `manifests/` | enough to verify a run |
| **prompt text from the public corpus** | `~/.cache/please-eval` | **never committed** — 41 upstream sources retain their own licences |
| scan results | `~/.cache/please-eval/results/<run>` | derived; reproducible from a manifest and a commit |
| model weights | `~/.cache/please-eval/models/<id>/<revision>` | gated/licensed upstream assets; never committed |

## The two thresholds

`gate` has a criterion and a baseline, and conflating them would make it useless.

* The **criterion** is SC-003's 1% false-positive budget. It is what the tool must eventually achieve, and
  on two slices it is currently not achieved.
* The **baseline** is what each slice achieves today, recorded in `corpus/slices.toml` as
  `baseline_permille`. The gate fails when a rate goes *above* its baseline.

So the gate is a tripwire on new damage, not a standing complaint. This is the pattern
`crates/core/tests/scaling.rs` already uses for the unmet 10 MB/s throughput criterion, and the reason is
the same: a gate that is red every day is a gate people route around. `gate --strict` enforces the
criterion, for when somebody wants to know whether it is met yet.

A gate-eligible slice with **no** baseline fails the gate. A floor that does not exist cannot be regressed
against, and a slice nobody has pinned would otherwise pass silently forever.

## What CI proves, and what it does not

`.github/workflows/ci.yml` runs the offline half on every change: the crate builds and tests, the
generated corpus regenerates byte-identically, and the gate runs over the negatives that can be
committed — the hand-written benign fixtures, the generated matched carriers, and every `.md` under
`docs/` and `specs/`.

That is a real gate and it catches a real class of regression: the security-prose slice fires on 14 of 55
of this repository's own documents, so a rule change that makes it 15 turns the job red.

It is **not** the public-corpus gate. OR-Bench, the stratified benign slices and the multilingual slice
need an approved gate on a gated dataset, which a CI runner does not have. Those are run by hand, and the
numbers land in `docs/research/eval-baseline.md` with the commit and rule-set digest that produced them.

`repo_prose` is also a **moving population**: adding a document to `docs/` or `specs/` changes both
numerator and denominator. That is deliberate. A new research memo that trips the scanner should require
a human to look at it and re-pin, rather than being averaged away.

## Layout

```text
src/slice.rs       corpus slice model — kinds, origins, caveated sources, the gate's config
src/cache.rs       where fetched text lives
src/fetch.rs       `hf datasets sql` invocation and cache materialisation
src/manifest.rs    row identity: why the content hash, and why sampling needs no seed
src/rows.rs        one scannable row and one row result, whatever the source
src/cases.rs       readers for the committed corpora
src/scan.rs        engine construction and the scan loop
src/run.rs         saved-run identity, atomic publication, completeness, and report assembly
src/metrics.rs     stratified aggregation, report rendering, the gate
src/generate.rs    carrier x payload x position, with span-level ground truth
src/models.rs      revision-pinned model acquisition, integrity, and bundle attribution
src/segment.rs     a local subset of `document-map.md` §1.1 — kinds, sibling groups, placement
src/outlier.rs     SC-603 and M2/M7: sibling-relative scoring, ranking, separation, model-free
src/ml.rs          real Candle CPU probes, only with `--features ml`
src/bench/         case packs, adapters, immutable runs, normalization, metrics, comparison
bench/             canonical system manifests and the context-aware protocol fixture
```

## Reading a number from this harness

Three things to check before quoting anything it prints.

**Which negative definition.** There are two, they differ by about a factor of two, and the earlier ad-hoc
runs used both without saying which — the confusion `docs/limits.md` records as *"produced against a
different assembly of the benign corpus and I could not reproduce them."* `neg_clean` is both labels zero;
`neg_nonadversarial` is `prompt_adversarial = 0` with harmful content permitted. A false-positive rate is
comparable only to another rate over the same definition.

**Whether a source is caveated.** SPML's rows all begin `[System: …]` because that is its serialisation
format, and the scanner fires on 400 of 400. So does TensorTrust, whose rows are labelled *adversarial* —
the identical non-fact reads as a 100% false-positive rate on one slice and a 100% detection rate on
another. Both are caveated in `corpus/slices.toml`, both are still reported, and neither counts toward a
gate.

**Never the aggregate.** Per-source detection on `pos_stratified` ranges from 0% to 100%. A mean over that
is a number without a referent, and `report` deliberately prints none for any multi-source slice.

The first [actual lab replay](../../docs/research/lab-replay-shart-2026-09-10.md) compares
20 SHART user inputs with its original PromptGuard + WulfRegex input scanner.

Tokenizer-verified boundary suites and overlap measurements use the shipping pipeline; see [BOUNDARY.md](BOUNDARY.md).


Judge response acceptance is versioned independently of request recipes. Inference metadata now
includes `response_acceptance_version`, `ordinary_max_response_bytes`, and `ml_max_response_bytes`.
Use a fresh run label for results produced under acceptance version `2026-09-12.1`; historical
structural responses without `stop_reason: "tool_use"` are rejected. Re-run those requests rather
than adding completion evidence to captured JSON. Prompts and request recipe hashes are unchanged
by this acceptance change.

## Hugging Face corpus reports

Corpus `run` commands now save `report.html`, `report.json`, and `report.md` beside the
identity-checked result rows. The default pipeline measures the shipping structural detector in product
mode with enforcement and the High threshold. Optional ML/judge tiers require explicit configuration.

Verify the cached inputs before measuring them, then choose a fresh run label:

```bash
cargo run --release --manifest-path crates/eval/Cargo.toml -- manifest \
  --slice pos_injecagent --slice pos_llmail --slice neg_orbench
cargo run --release --manifest-path crates/eval/Cargo.toml -- run \
  --run hf-product-high-next --slice pos_injecagent --slice pos_llmail --slice neg_orbench --tui
```

The terminal opens after completion. Reopen it without scanning again:

```bash
cargo run --release --manifest-path crates/eval/Cargo.toml -- view --run hf-product-high-next
cargo run --release --manifest-path crates/eval/Cargo.toml -- report \
  --run hf-product-high-next --format html --out /tmp/hf-report.html
```

Tabs cover datasets, source, technique, language, and coverage; arrows or j/k select rows;
PgUp/PgDn scroll details; q exits. Omit `--tui` for redirected/noninteractive runs.
`report --format table` prints a plain terminal summary.

Both views retain saved-run integrity and gate status. Incomplete and unverified runs remain visibly
partial. Negative-slice hit rates are false positives, and coverage cause counts can overlap:
they cannot be summed to infer unique incomplete rows. Product baselines remain unpinned until
deliberately established; meeting the false-positive criterion is distinct from passing a regression
gate. The report is artifact detection evidence, not contextual-alignment accuracy.

The first recorded three-slice run is documented in
[the September 14 measurement](../../docs/research/hf-product-high-2026-09-14.md).

## Reproducing historical detection experiments

Use the [current reproduction guide](../../docs/research/detection-reproduction-current.md)
for the frozen withdrawn email candidate, verified role-marker evidence, and
clean-baseline patch checks. Building today's detector does not reproduce the
historical email candidate's 510 InjecAgent detections.

The [all-rule matching audit](../../docs/research/matching-consistency-2026-09-15.md)
compares literal-gated matching with a test-only ungated reference. Its separate
HTML/TUI report shows paired dataset findings, detections, coverage gaps and
runtime costs, including five corrections deferred because they add benign findings.
Recount retained native evidence and open that report with:

```bash
python3 crates/eval/scripts/detection_experiment/report_matching_consistency.py \
  .cache/matching-consistency-20260915 --tui
```

The [cost attribution and fresh holdout follow-up](../../docs/research/prefilter-cost-2026-09-15.md)
records each correction's cost, the compacted gates, five individually rejected
rule expansions, and the freeze-first holdout. Recount its evidence and open the
HTML/TUI tables with:

```bash
python3 crates/eval/scripts/detection_experiment/report_prefilter_cost.py \
  .cache/prefilter-cost-20260915 --tui
```
