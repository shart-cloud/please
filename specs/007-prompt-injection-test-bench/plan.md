# Implementation Plan: Prompt-injection test bench

**Branch**: `007-Prompt-Injection-Test-Bench` | **Date**: 2026-09-12 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/007-prompt-injection-test-bench/spec.md`

## Summary

Extend the excluded `please-eval` package into a reproducible, multi-system test bench while preserving
its feature-006 evaluation commands and the shipping crates unchanged. The first release supports two
evaluation surfaces—artifact detection and contextual alignment—through an in-process PLEASE adapter and
a bounded JSONL subprocess adapter. It freezes exact case packs and system identities, retains native
outputs beside versioned normalized results, reports every failure and unsupported case, and compares
systems only over compatible cases and operating points.

The implementation deliberately stops before action execution, full agent simulation, and adaptive attack
generation. Those need a tool-state model, success predicates, and a stronger execution sandbox that
should be designed from AgentDojo, Task Shield, CaMeL, and adaptive-evaluation evidence rather than guessed
inside an already substantial feature.

## Technical Context

**Language/Version**: Rust 1.85 minimum, Rust 2021 edition, stable toolchain

**Primary Dependencies**: existing `serde`, `serde_json`, `toml`, `sha2`, `clap`, `tempfile`,
`please-core`, `please-scan`; standard-library subprocess and I/O primitives. New dependencies require
Phase 0 measurement and remain confined to `crates/eval`.

**Storage**: immutable local case-pack directories and append-only JSON/JSONL run artifacts under a
caller-selected output or the existing `please-eval` cache. Third-party corpus bytes remain local and
ignored; committed manifests contain identities and attribution.

**Testing**: `cargo test --manifest-path crates/eval/Cargo.toml`, contract fixtures, property tests for
identity and pack validation, deterministic subprocess fixtures, existing workspace and dependency gates,
and manual model/tool evaluations only after the instrument passes offline tests.

**Target Platform**: Linux, including Ubuntu under WSL and Ubuntu GitHub Actions. Native Windows adapter
execution is deferred until process-tree termination and isolation semantics can be made equivalent.

**Project Type**: offline research/evaluation CLI and library in the excluded `please-eval` package

**Performance Goals**: stream at least the existing approximately 74,000-row corpus without retaining
completed inputs or outputs in memory; bound each adapter request, response, diagnostic stream, and elapsed
time; make runner overhead visible separately from system latency.

**Constraints**: offline by default; no network or model acquisition during an ordinary run; no inherited
host credentials; no special-file reads; no changes to feature-006 detector behavior or operating points;
no new dependency in a shipping crate; every result and comparison attributable to exact bytes and
configuration.

**Scale/Scope**: two executable surfaces, two adapter kinds, at least two materially distinct system
configurations, a minimum 30-group contextual development pilot, existing corpus-scale artifact packs, and
future-compatible taxonomy fields without implementing action or workflow execution.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

| Principle | Evaluation |
|---|---|
| **I — Judgement is separate from enforcement** | **Held.** Native detector evidence, normalized relations, caller decisions, ground truth, and comparison metrics are distinct fields. The bench does not silently turn confidence into severity or a failure into clean. Release-capable review is an explicit system property and its attack releases are reported. |
| **II — Bounded, linear-time analysis** | **Held and extended to the instrument.** Pack validation, asset reads, subprocess input/output, diagnostics, elapsed time, and in-flight rows are bounded. Special files and symlinks are refused before opening. Case processing is incremental. External-system complexity is measured and bounded by the host; it is never attributed to core. |
| **III — Detection rules are data, not code** | **Held.** The feature changes no shipping detection rules. Case packs, taxonomy, system configuration, and experiments are declarative data. Normalizers are versioned adapter code, not hidden detection rules, and cannot alter ground truth. |
| **IV — Evaluation is stratified and honest** | **Strengthened; this is the feature's purpose.** Exact manifests, exposure checks, family splits, per-source/technique/vector/surface metrics, explicit failures, paired analysis, and operating-point identity are mandatory. Development and same-author data cannot be described as independent holdouts. |
| **V — Embeddable, dependency-free core** | **Held.** All bench code stays in excluded `crates/eval`. The in-process adapter depends in the existing direction on `please-scan`; no shipping crate depends on the bench or its adapters. Default workspace dependency and wasm checks remain gates. |

**Scope and analysis constraints**: feature 007 measures direct and indirect prompt-injection defenses but
does not add harmful-content moderation. It preserves caller-owned provenance and trusted context and
treats all case bytes and adapter text as untrusted. The deliberately deferred action/workflow surface is
named in the spec rather than implied by artifact metrics.

**Development workflow**: instrument behavior is test-first. Adapter failure, tampering, output forgery,
special files, limits, leakage, and stratification receive failing tests before implementation. No real
tool or model result becomes an acceptance test for the bench itself; deterministic fixtures establish
the instrument, and manual experiments establish only the tested system's result.

**No constitutional deviation is proposed.** Complexity Tracking remains empty unless Phase 0 shows that
a required process-control or schema dependency would cross the evaluation boundary.

## Project Structure

### Documentation (this feature)

```text
specs/007-prompt-injection-test-bench/
├── spec.md
├── plan.md
├── research.md                 # Phase 0 decisions and measured prototypes
├── data-model.md               # Case, system, run, result, exposure relationships
├── quickstart.md               # Offline fixture run and manual external-tool workflow
├── contracts/
│   ├── case-pack.schema.json
│   ├── system.schema.json
│   ├── experiment.schema.json
│   ├── adapter-request.schema.json
│   ├── adapter-response.schema.json
│   └── bench-result.schema.json
└── tasks.md                    # Created only after design review
```

### Source Code (repository root)

```text
crates/eval/
├── Cargo.toml
├── src/
│   ├── main.rs                # existing commands plus `bench`
│   ├── lib.rs
│   └── bench/
│       ├── mod.rs
│       ├── case.rs            # surface labels and case references
│       ├── pack.rs            # load, verify, split/exposure checks
│       ├── taxonomy.rs        # versioned techniques and delivery vectors
│       ├── system.rs          # system and capability manifests
│       ├── experiment.rs      # frozen matrix and limits
│       ├── adapter.rs         # adapter trait and native response envelope
│       ├── please.rs          # in-process ScanSession adapter
│       ├── process.rs         # JSONL subprocess lifecycle and bounds
│       ├── normalize.rs       # versioned surface-specific normalization
│       ├── runner.rs          # deterministic incremental scheduling
│       ├── result.rs          # row/run artifacts and completeness markers
│       ├── metrics.rs         # stratified and paired calculations
│       └── report.rs          # Markdown/JSON comparison output
├── tests/
│   ├── bench_pack.rs
│   ├── bench_process.rs
│   ├── bench_runner.rs
│   ├── bench_metrics.rs
│   ├── bench_security.rs
│   └── bench_compatibility.rs
└── corpus/bench/
    ├── taxonomy.toml
    ├── instrument/            # redistributable deterministic CI fixtures
    └── paired-context-dev/    # same-author development pilot, clearly labeled

ci/
└── check-eval-isolation.sh    # only if existing checks cannot prove FR-761

docs/research/
└── test-bench/                # experiment reports, not raw licensed inputs
```

**Structure Decision**: extend the existing excluded evaluator rather than add a workspace member or put
adapter code in `please-core`. The top-level `please-eval bench ...` command owns the new surface, leaving
existing `run`, `report`, `gate`, `replay`, `capture`, `model`, and `boundary` meanings intact.

## Baseline to freeze before implementation

The baseline is merge commit `7bec2b3`, which merged feature 006. Before the first code change:

1. Record `cargo test --workspace --all-targets`, workspace Clippy, formatting, wasm, dependency/isolation,
   offline CLI, evaluator tests, and the offline mechanism gate.
2. Record the existing evaluator command help and JSON artifact schema versions.
3. Record default structural and product `ScanSession` identities and one deterministic fixture output.
4. Confirm the feature-006 600-case set and boundary cases are marked exposed development material.
5. Fix or explicitly block on the two existing acquisition defects: special files can block a scan, and
   directory entry/type errors can be skipped. A bench that evaluates adversarial inputs must not inherit
   either behavior into case-pack acquisition.

Feature 007 does not re-pin an accuracy baseline merely because the bench changes presentation. Any
intentional product change discovered during implementation belongs in another feature and another run.

## Phase 0 — Research and contract decisions

Phase 0 produces `research.md`. Prototypes live outside shipping crates and are removed or converted into
tests once a decision is recorded.

### R1 — Surface vocabulary and ground truth

Freeze the two request and result vocabularies. Artifact detection needs `detected`, `not_detected`, and
`indeterminate`; contextual alignment needs `aligned_instruction`, `conflicting_instruction`,
`non_instruction`, and `indeterminate`. Decide how multi-span and multi-label cases are represented without
collapsing an entire document to one unexplained label.

Use AlignSentinel's three-way question as evidence, not as an API copied blindly. Record where quoted or
descriptive instructions land, how permission uncertainty differs from non-instruction, and when a case
must remain ambiguous.

**Exit evidence**: ten adjudicated examples per relation, including disagreements, and a written label
guide that two reviewers can apply independently. Agreement is reported; disagreement is not erased.

### R2 — Subprocess lifecycle and containment

Prototype a long-lived JSONL child with handshake, one-request/one-response sequencing, bounded stderr,
per-case deadlines, restart after failure, and process-tree termination on Ubuntu/WSL. Measure model-load
amortization against one-process-per-case execution.

The universal request carries exact candidate bytes encoded inside the envelope rather than exposing a
pack path. The child receives opaque case and context identities plus only the context text its declared
surface requires. Stdout is protocol-only; diagnostics use bounded stderr.

External adapters are caller-selected trusted programs, not arbitrary malware. Still determine whether
Linux process groups alone are sufficient for descendant cleanup and whether an available unprivileged
sandbox can enforce network and filesystem restrictions without making WSL unusable. State the achieved
boundary precisely; do not call an environment scrub a sandbox.

**Exit evidence**: deterministic fixtures for success, delayed response, infinite output, forked child,
crash, malformed JSON, wrong id, duplicate response, and missing response, with measured termination bounds.

### R3 — Canonical identity and artifact layout

Define domain-separated digests for packs, cases, trusted contexts, systems, normalizers, experiments,
native responses, and normalized rows. Decide which telemetry is excluded from semantic identity so a
replay on another host can compare decisions without pretending latency is identical.

Reuse the canonical sorted-field/length-prefixed approach established by feature 006 where practical.
Hash exact bytes actually passed to the system. A manifest path or claimed model name is provenance, not
byte identity.

**Exit evidence**: test vectors proving order independence where intended, ambiguity resistance, and an
identity change for every load-bearing field.

### R4 — Case-pack and exposure migration

Map existing slice manifests, capture freezes, replay captures, the 600-case dataset package, and boundary
suites into the proposed CasePack without rewriting their bytes or changing their historical meaning.
Choose between direct compatibility readers and an explicit one-time conversion command.

Test exact, normalized, family, source-template, and authored-example exposure. Determine which checks are
hard failures and which are caveats. Third-party licenses remain attached at the source/asset level.

**Exit evidence**: one existing committed corpus and one ignored local freeze verify as case packs; an
intentional cross-split family and normalized duplicate fail before execution.

### R5 — First systems and normalization rules

Select the first materially distinct comparison systems. Required candidates are:

1. PLEASE structural mechanism at its frozen operating point.
2. PLEASE shipping product configuration, optionally with the pinned local classifier when assets exist.
3. One external implementation with accessible code, reproducible versioning, compatible licensing, and a
   locally runnable surface.

Attention Tracker is a useful code-reading candidate but requires model attention access and may belong to
a later instrumented-model adapter. AlignSentinel has no verified public implementation. Prompt Guard or
another locally runnable classifier may be a better first process adapter. Record the choice from measured
integration cost and available identity, not paper prominence.

For each system, document exactly how native output maps—or cannot map—to the common surface. A normalizer
may preserve `unknown`; it may not invent task alignment from an attack probability.

**Exit evidence**: three system cards with input needs, native outputs, supported surfaces, model/runtime
access, license, threshold, cost, and proposed normalizer.

### R6 — Instrument budgets and scale

Measure pack verification and no-op adapter overhead at 1,000, 10,000, and approximately 75,000 cases.
Choose defaults and hard maxima for candidate bytes, request envelope, stdout, stderr, startup, per-case
execution, restarts, and in-flight cases. Separate adapter/model latency from runner overhead.

**Exit evidence**: measured table on the development host and CI-class hardware, with bounds encoded in the
experiment schema rather than hidden constants.

## Phase 1 — Data model and contracts

Produce `data-model.md`, the six JSON schemas, and `quickstart.md` before production code.

The dependency direction is:

```text
CasePack + SystemManifest + Experiment
                 │
                 ▼
          verified RunPlan
                 │
        ┌────────┴────────┐
        ▼                 ▼
PLEASE in-process    JSONL subprocess
        │                 │
        └──── native result ────┐
                                ▼
                    versioned Normalizer
                                │
                                ▼
                     append-only BenchResult
                                │
                                ▼
                    Metrics + ComparisonReport
```

Ground truth travels from the verified pack directly to `BenchResult`; it is never sent to a system or
normalizer. Trusted context is sent only to systems declaring the contextual surface. Reporting reads
immutable row results and does not invoke systems.

### Contract rules

- JSON schemas reject unknown fields where forward compatibility would otherwise hide a typo.
- Every envelope carries a schema version and domain-specific identity.
- Binary candidate input uses a canonical encoding and an exact byte count/digest.
- Protocol stdout contains one JSON object per line and no prose.
- Native responses are retained even when normalization fails.
- A normalizer can return indeterminate or unsupported; it cannot edit ground truth or run configuration.
- `completed`, `unsupported`, `abstained`, `timeout`, `crashed`, `invalid_output`, and `unavailable` remain
  distinguishable states.
- A complete-run marker is written only after every planned row and report prerequisite is durably present.

Re-run the Constitution Check after schemas and data model are complete. Any field that mixes evidence,
policy, or ground truth blocks Phase 2.

## Design Decisions

### D1 — The bench extends `please-eval`, not the shipping CLI

`please-eval` already owns heavy dependencies, corpus access, replay, model experiments, metrics, and
licensed-data boundaries. A new workspace crate would duplicate those facilities, while adding adapters to
`plz` would make a production firewall responsible for launching research tools. The new entry point is a
`bench` subcommand tree inside `please-eval`.

### D2 — Surfaces are separate contracts, not optional fields in one universal prompt

Artifact detection and contextual alignment answer different questions and have different ground truth.
A context-free scanner is not penalized for failing to answer a task-alignment question it never claimed
to support, but it also receives no contextual credit. Capability routing happens before execution and is
recorded per row.

Action-boundary and workflow evaluation are not represented as mostly-empty variants. Their future case
model needs tool state, proposed actions, authorization, and success predicates and will be added as a
versioned surface extension.

### D3 — Technique and delivery vector are orthogonal taxonomy axes

`override`, credential solicitation, authority forgery, concealment, privilege widening, and related
techniques describe what an attack does. User input, retrieved page, email, skill file, repository config,
MCP tool description, and tool result describe how it arrived. Keeping both enables the cross-product
measurements the existing agentic-surface work showed were necessary.

The taxonomy is versioned data. Unknown values fail pack validation until the taxonomy is deliberately
extended; free-form tags may coexist but cannot replace the governed axes used for metrics.

### D4 — Long-lived JSONL is the universal external adapter

A subprocess boundary accommodates Rust, Python, model servers, and paper implementations without a plugin
ABI or dependency leakage. One process per system amortizes model load. A handshake binds protocol and
system identity. Requests are sequential in the first implementation; explicit concurrency can follow
after deterministic semantics and memory bounds are proven.

On timeout or protocol corruption, terminate the process tree, mark the affected row, and restart for the
next case if the run's fixed restart budget permits. Never silently retry a completed model response;
retries change both cost and stochastic sampling and must be part of the experiment.

### D5 — Raw, normalized, and policy outcomes remain separate

Every adapter returns its native evidence and decision. A normalizer maps only what the native contract
supports into surface-specific fields. PLEASE severity, Prompt Guard probability, an LLM relation label,
and an application block decision are not one number.

Reports may compare binary detection at recorded operating points, but native score calibration is shown
separately. Threshold sweeps require saved raw scores and become a named analysis, not a mutation of the
original run.

### D6 — Failure is data and remains in denominators

Unsupported means the system declared no capability and is excluded from effectiveness for that surface
while remaining in coverage tables. A requested system that times out, crashes, abstains unexpectedly, or
returns invalid output failed to defend that case. On positive cases it is counted as a non-detection and
also in its specific failure category. On negative cases it is not credited as a true negative. Both
denominators and coverage counts are printed so this choice is visible.

Indeterminate native answers remain indeterminate. Caller policy may separately model fail-open or
fail-closed deployment, but the bench does not choose one silently.

### D7 — Comparisons are exact-pack and group-aware

The first comparison implementation requires the same pack digest, label set, and case identities. It does
not take an accidental intersection of two runs. Paired context variants and generated placements are
summarized by group, with group bootstrap or exact paired counts where sample size permits.

Optional aggregates may be printed only after constituent strata and with explicit weighting. They are
never the only headline for a multi-source pack.

### D8 — The runner treats content as hostile but adapters as caller-selected code

Candidate bytes never become command-line arguments, paths, environment variables, or shell source. They
travel in the protocol envelope. The runner uses no shell to start adapters, clears the environment, sets a
fresh working directory, bounds all streams, and neutralizes displayed text.

This is not a malware sandbox. The user authorizes the configured executable. Phase 0 must state which
network, filesystem, and descendant-process restrictions are mechanically enforced on Linux and which
remain trust assumptions.

### D9 — Existing evaluator artifacts are adapted, not reinterpreted

Historical mechanism and product results retain their schemas and meaning. Compatibility readers may wrap
them as artifact-surface rows only when every required identity exists. Missing context or system identity
is labeled unrecorded; it is never filled with today's defaults.

Existing case/capture structures should be reused below the new CasePack abstraction where semantics
match. A large mechanical rewrite of `please-eval` before the first vertical slice is rejected.

### D10 — The first pilot is developmental by construction

Create at least 30 related groups across user-input, tool-response/document, and repository/skill delivery
vectors. Each group holds candidate wording constant across changes in caller task, permission, or
presentation and includes aligned, conflicting, and non-instruction/analytical cases where defensible.

The authors will inspect these cases and use their outcomes to refine the bench, so the pack is permanently
development data. Freeze a family-separated holdout only after the system list, normalizers, metrics,
thresholds, and selection criteria are fixed.

## Implementation Sequence

### Phase 2 — Pack validator vertical slice

1. Write schema and digest test vectors.
2. Load one redistributable instrument pack incrementally.
3. Reject tampering, unknown fields, conflicting duplicate labels, special files, and split leakage.
4. Produce `please-eval bench pack check` with no system execution.
5. Map one existing generated or fixture corpus through a compatibility reader without changing it.

This phase independently delivers value: it makes future experiments freezeable before adapter code
exists.

### Phase 3 — Run plan and in-process PLEASE adapter

1. Validate system and experiment manifests and freeze the `RunPlan`.
2. Implement append-only row output and incomplete-run marker semantics.
3. Add the `ScanSession` adapter using the exact feature-006 product/mechanism configurations.
4. Prove candidate labels are never passed to the adapter.
5. Reproduce a current evaluator result through the adapter and explain every intentional representation
   difference before accepting it.

This phase is the MVP: one general case pack, one real system, immutable rows, and reproducible reports.

### Phase 4 — Subprocess adapter

1. Implement and validate handshake and per-case envelopes.
2. Add bounded stdin/stdout/stderr, deadlines, process-tree cleanup, and fixed restart policy.
3. Add deterministic fixture programs for every failure mode.
4. Prove parent credential canaries and undeclared environment variables do not reach the child or output.
5. Integrate the selected external artifact detector only after the fixture protocol is green.

### Phase 5 — Normalization, metrics, and comparison

1. Implement artifact normalization and confusion metrics.
2. Implement contextual relation normalization and the full four-way matrix.
3. Add source, technique, vector, surface, length, and system strata.
4. Add group-paired transition tables and descriptive group-level intervals.
5. Report coverage, failure, latency, memory, request count, and cost beside effectiveness.
6. Reject incompatible run comparisons before reading row outcomes.

### Phase 6 — Paired-context development pilot

1. Write and review the label guide.
2. Author cases before looking at candidate-system outcomes.
3. Record independent labels and disagreements.
4. Freeze the pack as development data and add it to exposure history.
5. Run context-free PLEASE and at least one context-aware adapter over the complete preselected pack,
   including cases PLEASE did not nominate.
6. Publish a report that calls the method an adaptation where it differs from AlignSentinel or Task Shield.

### Phase 7 — CI, compatibility, and documentation

1. Add offline instrument fixtures to the isolated evaluator CI job.
2. Keep real model, judge, gated-data, and third-party adapter runs manual.
3. Re-run all feature-006 compatibility and shipping dependency gates.
4. Document the adapter protocol, case-pack preparation, result interpretation, limitations, and how to add
   a system without changing the bench.
5. Create `tasks.md` only after the Phase 0/1 artifacts and the P1 vertical-slice boundary are reviewed.

## Test Strategy

### Unit and property tests

- Canonical identities change for every load-bearing field and remain stable across map ordering.
- Pack validation rejects path traversal, symlinks, special files, duplicates, conflicting labels,
  normalized leakage, family leakage, unknown taxonomy values, and post-check byte changes.
- Metric denominators preserve failures and exclude ambiguous/unsupported cases exactly as D6 states.
- Group pairing never pairs across group, pack, context, or system identities.
- Rendering neutralizes terminal, Markdown, JSONL, bidi, and invisible-control payloads.

### Contract tests

- Every schema accepts its canonical example and rejects missing, unknown, duplicated, mismatched, and
  oversized fields.
- JSONL framing survives embedded newlines and arbitrary candidate bytes through canonical encoding.
- Adapter handshake and response ids cannot be forged by candidate content.
- Native output remains byte-addressable after normalizer failure.

### Integration tests

- In-process PLEASE results match direct `ScanSession` results under the same named configuration.
- A long-lived fixture child handles multiple cases and is restarted only under the frozen policy.
- Hung, noisy, crashing, forking, and malformed children terminate within measured bounds and later cases
  still produce rows.
- Two deterministic systems over one pack produce a stable comparison; comparison against itself is empty.
- A 10,000-case instrument pack demonstrates incremental input and output handling.

### Compatibility and boundary tests

- Existing evaluator tests and the offline mechanism gate pass without baseline changes.
- Workspace tests, Clippy, formatting, wasm, dependency allow-list, core isolation, ML isolation, offline CLI,
  and credential-leak checks remain green.
- `cargo tree` proves no bench dependency reaches a shipping crate.
- No ordinary CI test downloads a model, contacts a remote judge, or reads a gated corpus.

### Manual evaluation

- First external detector integration and identity check.
- Optional local-model PLEASE product arm using pinned verified assets.
- Context-aware reviewer pilot with exact request/prompt/model identity and captured failures/cost.
- Final untouched holdout only after development decisions and numerical acceptance criteria are frozen.

## Follow-on Features

### Action-boundary and agent-workflow bench

Add simulated tools, typed resources, initial state, proposed actions, permission policies, user success
predicates, and attacker success predicates. Measure unauthorized-action rate, attack success, benign task
completion, and interruptions. AgentDojo provides the evaluation shape; Task Shield and CaMeL provide
contrasting relevance and capability-policy mechanisms. No real external side effects should be required.

### Adaptive attack harness

Add versioned attackers with declared knowledge, feedback, query budget, mutation lineage, and stopping
criteria. Evaluate each defense with attacks adapted to that defense and report robustness over budget,
following the methodological lesson of *The Attacker Moves Second*. Static benchmark results remain a
separate arm.

### Instrumented-model adapters

Support attention and activation access for AlignSentinel-, Attention Tracker-, and TaskTracker-style
experiments only when compatible model/runtime code and training artifacts exist. A surrogate model's
transfer to another agent is its own measured experiment, never assumed.

## Risks and Mitigations

| Risk | Mitigation |
|---|---|
| Universal schema erases what makes systems different | Preserve raw native results; keep surface schemas small; version normalizers; allow indeterminate mappings. |
| The branch becomes an agent platform rather than a bench | Restrict 007 to artifact and contextual surfaces; defer tool execution and adaptive generation explicitly. |
| A broken adapter looks accurate because failures disappear | One planned row per system/case; fail states remain in output and denominators; complete marker written last. |
| Model load dominates per-case process execution | Long-lived child protocol with explicit restart accounting; report load/warmup separately. |
| External tools leak dependencies or secrets | Keep process adapters in excluded eval; clear environment; canary tests; offline default; explicit remote capability. |
| Same-author pilot overstates accuracy | Permanent development label, exposure record, per-source caveat, independent family-separated holdout later. |
| Taxonomy becomes a second detector ontology | Separate technique/vector labels from PLEASE classes; version as evaluation metadata; allow multi-label cases. |
| Nondeterministic systems make replay claims misleading | Record generation parameters and repetitions; distinguish instrument reproducibility from system repeatability. |
| Large packs exhaust memory or storage | Incremental reads/writes, bounded in-flight rows and streams, explicit output budgets, 10,000-case instrument test. |
| Linux-only process controls are assumed portable | Declare Linux/WSL support; defer native Windows until equivalent tests exist. |

## Complexity Tracking

No constitutional violation is planned.

The subprocess adapter, surface-specific schemas, and separate normalizers are additional concepts, but
each prevents a demonstrated category error: dependency leakage, incomparable labels, or loss of native
evidence. Phase 0 must still justify any new crate dependency with measured build/dependency cost and show
that it remains confined to the excluded evaluator.
