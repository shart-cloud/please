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
cargo run --manifest-path crates/eval/Cargo.toml -- run --offline
cargo run --manifest-path crates/eval/Cargo.toml -- report --offline
cargo run --manifest-path crates/eval/Cargo.toml -- gate --offline      # exits 2 on a regression

# The public corpus — needs the `hf` CLI and an approved dataset gate
hf auth whoami
cargo run --manifest-path crates/eval/Cargo.toml -- fetch
cargo run --manifest-path crates/eval/Cargo.toml -- manifest            # verify cache against manifests
cargo run --release --manifest-path crates/eval/Cargo.toml -- run
cargo run --release --manifest-path crates/eval/Cargo.toml -- report --out /tmp/report.md
```

Use `--release` for the public corpus. A debug build scans 60,000 rows at roughly a tenth of the speed;
the results are identical either way, which is the point of SC-011.

## What is committed and what is not

| | where | why |
|---|---|---|
| slice definitions, carriers, payloads, positions | `corpus/` | reviewable inputs |
| the generated corpus | `corpus/generated.jsonl` | generated text is ours to redistribute |
| row identity, labels, source, content hashes | `manifests/` | enough to verify a run |
| **prompt text from the public corpus** | `~/.cache/please-eval` | **never committed** — 41 upstream sources retain their own licences |
| scan results | `~/.cache/please-eval/results/<run>` | derived; reproducible from a manifest and a commit |

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

That is a real gate and it catches a real class of regression: the security-prose slice fires on 13 of 41
of this repository's own documents, so a rule change that makes it 14 turns the job red.

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
src/metrics.rs     stratified aggregation, report rendering, the gate
src/generate.rs    carrier x payload x position, with span-level ground truth
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
