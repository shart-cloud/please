# Feature 007 future-phase handoff

**Last updated**: 2026-09-15
**Branch**: `007-Prompt-Injection-Test-Bench`
**Implementation baseline**: `90f5676` (`feat(eval): add prompt-injection test bench`)
**Next scope**: remediation Phase 4, then Phase 5

## September 15 checkpoint

The September 13 baseline below describes the committed bench implementation before the subsequent
presentation and detector work. The latest detector checkpoint is
[`docs/research/prefilter-cost-2026-09-15.md`](../../docs/research/prefilter-cost-2026-09-15.md),
with its companion HTML, verified JSON, and baseline/candidate rule snapshots now present in the repo.
The local evidence verifier has rechecked all 51 native runs. The current detector sources and built-in
rules match the frozen performance candidate.

Work completed since the baseline:

- HTML/table exports and terminal browsers for verified bench and corpus results; corpus coverage
  reports count distinct incomplete rows separately from overlapping causes.
- Withdrawal of the email-transmission candidate from shipping defaults; its historical grammar and
  evidence remain separate from authorization regressions.
- Role-marker admission and thirteen-rule matching corrections, followed by literal compaction that
  retains the recovered 2,251 generated syntax detections and measured natural-corpus findings.
- Five broader literal corrections remain deferred because each exposes ordinary-language findings.
- Fresh within-source validation and performance evidence, plus report regressions wired into CI.

Use [`docs/research/detection-reproduction-current.md`](../../docs/research/detection-reproduction-current.md)
to choose the correct frozen detector for historical replays. The 587-row September 15 holdout is now
exposed; it must be excluded from any future fresh selection. Local corpus bytes and frozen executables
remain under `.cache/` and are not distributed with the source reports.

**Next implementation task remains 4.1 below.** The presentation work did not consolidate saved-run
storage or identity handling, and it does not establish completion of the Phase 5 terminal-escaping
requirement across every CLI path. Preserve the existing report interfaces and formats during cleanup.

## Start here

Read these in order:

1. `remediation-plan.md` — the authoritative remaining work and acceptance tests.
2. `spec.md` — requirements, claims, and explicit scope boundaries.
3. `crates/eval/BENCH.md` — the operator and adapter contract.
4. `quickstart.md` — the shortest end-to-end verification path.
5. `pilot-results.md` — the current development-pilot evidence and its caveats.

This handoff is a map, not a replacement for the remediation plan. If the two disagree, update this file
to match a deliberately revised remediation plan rather than silently implementing a third design.

## Current state

Feature 007 and remediation Phases 0 through 3 are implemented in `90f5676`. The working tree was clean
immediately after that commit.

The implementation currently provides:

- versioned, identity-bound pack, taxonomy, system, experiment, protocol, result, and run contracts;
- an in-process PLEASE adapter that reuses `product::Runtime` and a bounded long-lived subprocess adapter;
- exact native-output preservation with surface-specific normalization;
- row-level coverage for unsupported input, abstention, timeout, crash, malformed output, and exhaustion;
- atomic complete-run publication, strict compatible-run comparison, exposure records, and stratified reports;
- order-independent pack checks, declared contextual baselines, and a complete 4-by-4 relation matrix;
- one case-wide subprocess deadline, stable crash status, process-level stderr telemetry, bounded stdout,
  restart limits, process-group cleanup, and run-owned verified executable copies;
- an exposed first-party development pilot containing 30 groups, 120 cases, and 240 result rows.

The latest committed pilot report identifies run
`c948802e51c2d7ea778879c173acf246cc2c92f985ae782b650fa5987a3216fa`. It is instrument evidence, not
deployment accuracy. The Python contextual adapter is a deterministic fixture, not a recommended defense.

## Invariants to preserve

- Do not change the feature-006 shipping detector, rules, threshold, or default CLI behavior as part of
  bench work.
- Keep the bench inside the excluded `crates/eval` crate. No bench or adapter dependency may reach a
  shipping crate.
- Treat corpus bytes as hostile data and system manifests as trusted executable configuration.
- Never execute tools or agents from a test case. Feature 007 evaluates artifact detection and contextual
  alignment only.
- Preserve failures as rows. A timeout, crash, unsupported input, or malformed response must never become
  a clean decision or disappear from a denominator.
- Preserve raw system output separately from normalized labels. Artifact and contextual normalizers must
  remain separate.
- Do not compare runs unless their pack, system, normalizer, and operating-point identities are compatible.
- Do not claim that `network_capable: false` is a network sandbox. Only a recorded `sandbox_command` is an
  enforcement hook, and the report must continue to distinguish it from declared-offline execution.
- Do not overwrite packs, exposure ledgers, or run directories. Identity and append-only behavior are part
  of the evidence model.
- Use integer counts and per-mille metrics; do not introduce floating-point report drift.

## Next implementation phase: Phase 4 consolidation

Phase 4 is cleanup rather than a measurement blocker. Preserve serialized formats and behavior while
removing duplication. Land each numbered item separately so regressions have a narrow cause.

### 4.1 Extract one saved-run module

Start here. `crates/eval/src/run.rs` and `crates/eval/src/bench/runner.rs` both own atomic publication,
completion records, result digests, and verification. Extract `eval::saved_run::SavedRun<Row>` and move
both callers onto it.

Important constraints:

- keep existing run and bench files readable unless a schema/version bump is intentional;
- retain create-new behavior for pending files and directory syncing;
- add the planned test proving that neither caller publishes over an existing `.pending` file;
- use the existing `run_integrity.rs`, `saved_run.rs`, and `bench.rs` tests as characterization tests;
- consolidate `bench::report::{MetricCounts, RelationMatrix}` with the compatible types in `metrics.rs`
  only after the saved-run seam is stable.

### 4.2 Product runtime adapter

Already completed as part of remediation Phase 2. Do not redo it. The current bench system contract still
configures structural product/mechanism modes only. ML and judge configuration remains a follow-on contract
change because model paths, credential policy, and network permission are not represented today.

### 4.3 Promote identity handling

Promote `bench/identity.rs` to `eval::identity`, then migrate `run`, `manifest`, `capture`, `replay`,
`boundary`, and `models`. The bench implementation is the hardened version: preserve lowercase-hex
validation, path safety, bounded reads, and domain separation.

Done means no SHA-256 construction remains outside the shared identity module. Search for
`Sha256::new()` to prove it, then run every existing digest and replay test unchanged.

### 4.4 Fold shallow bench modules

Move the small adapter, protocol, and exposure data types into `bench/model.rs`. Keep `please.rs` and
`process.rs` as the two execution adapters. Remove only the dead fields and helpers named in the remediation
plan; do not combine this step with a protocol or schema redesign.

### 4.5 Move gate and selection logic out of the binary

Move `check_gate`, `select`, and `write_report` behavior from `main.rs` into library functions in `metrics`
and `run`. Leave command parsing and exit-code mapping in the binary. Add direct tests for incomplete runs,
unverified runs, and below-baseline gates.

### 4.6 Finish module navigation

Expand `bench/mod.rs` with the same kind of ownership table and boundaries already present in `lib.rs`.
This should describe the post-consolidation layout, not the layout that existed before 4.1 through 4.5.

## Final feature phase: Phase 5 gaps

After Phase 4 is green, close or explicitly defer every remaining row in the Phase 5 table. A practical
order is:

1. FR-738: escape control characters in terminal output.
2. FR-763: validate every committed manifest against the committed JSON schemas in tests.
3. FR-748: capture child peak memory with `getrusage` and report it without changing decision semantics.
4. US2 Scenario 4: add explicit `context_withheld: true` support and the required indeterminate behavior.
5. FR-747: add separate released-attack and removed-benign-interruption outcomes for release-authority
   systems.
6. SC-708: turn the 10k scale probe into an ignored release-quality test that asserts the configured
   in-flight bound.
7. FR-731: add the written bounded-manifest/streamed-assets deferral to `docs/limits.md`.

Any contract change must update the Rust model, its committed JSON schema, fixtures/examples, strict
unknown-field tests, and the documented version together. Regenerate the pilot after Phase 5 and explain
every metric change in `pilot-results.md`; do not copy new numbers without interpreting the delta.

Still explicitly deferred beyond Feature 007:

- ML and judge tier configuration in bench system manifests;
- an independent second label pass;
- selection and licensing of a pinned third-party detector or model;
- a family-separated untouched holdout frozen only after systems and normalizers are fixed;
- group-level uncertainty statistics beyond the required directional paired comparison.

The last three evidence items require a human decision or third-party asset. Do not fabricate them or mark
them complete because the harness can represent them.

## Validation ladder

Run the narrow checks after each commit and the full ladder before declaring a phase complete.

```bash
cargo fmt --manifest-path crates/eval/Cargo.toml --check
cargo clippy --manifest-path crates/eval/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path crates/eval/Cargo.toml
cargo test --manifest-path crates/eval/Cargo.toml \
  --features shipping-judge,shipping-ml --test product --test boundary

cargo test --workspace --locked --no-fail-fast
./ci/check-dependencies.sh
./ci/check-core-isolation.sh
bash ci/check-cli-dependencies.sh
bash ci/check-ml-isolation.sh
```

Then verify the committed bench inputs from the repository root:

```bash
cargo run --manifest-path crates/eval/Cargo.toml -- \
  bench pack check \
  --pack crates/eval/corpus/bench/contextual-pilot/pack.json

cargo run --manifest-path crates/eval/Cargo.toml -- \
  bench experiment \
  --manifest crates/eval/bench/contextual-pilot.experiment.json
```

For subprocess lifecycle changes, also stress the relevant fixture tests repeatedly under parallel load;
the remediation completion criterion is 50 consecutive runs with `--test-threads=8` while a workspace
build runs alongside. Avoid replacing construction-based timing tests with fragile wall-clock thresholds.

The pilot generator never overwrites an existing directory. Generate proposed corpus changes into a new
temporary directory, review the recursive diff, and replace committed material only when the contract or
intended corpus actually changed:

```bash
cargo run --manifest-path crates/eval/Cargo.toml \
  --example generate_bench_pilot -- /tmp/contextual-pilot-next
```

## Completion checklist

Phase 4 is complete when both saved-run callers use the shared implementation, all hashing uses the shared
identity module, the shallow modules and binary wiring are consolidated, and all existing serialized
artifacts still verify.

Feature 007 is complete when every Phase 5 row is implemented or truthfully documented as deferred, the
spec status matches that reality, the full validation ladder passes, and the regenerated pilot report keeps
its development/evidence caveats. Leave the human/manual tasks unchecked until the corresponding evidence
actually exists.
