# Feature Specification: Prompt-injection test bench

**Feature Branch**: `007-Prompt-Injection-Test-Bench`

**Created**: 2026-09-12

**Status**: Implemented except release-review outcomes (FR-747); US2 Scenario 4 is unreachable; SC-708 is manual; ML and judge tiers are intentionally deferred because the bench contract does not yet carry their configuration or credential policy

**Input**: Extend PLEASE from a scanner with a product-specific evaluation harness into a reproducible
test bench for comparing prompt-injection techniques, detectors, and context-aware defenses. Preserve the
shipping scanner's small trusted core and the frozen feature-006 baseline.

---

## Problem statement

`please-eval` can already freeze corpora, run the shipping `ScanSession`, preserve exposure history,
measure model window boundaries, replay captured results, and report source-stratified metrics. It cannot
yet describe another detector as a system under test, run several systems over the exact same cases, or
compare context-free detection with a defense that receives the caller's trusted task and permissions.

That gap makes research conclusions difficult to reproduce. A classifier score, a structural finding,
and an alignment judgement answer different questions, yet ad-hoc experiments tend to flatten them into
one severity or compare them on different samples. Tool failures, unsupported inputs, changed thresholds,
and exposed holdout cases are also easy to lose between scripts.

This feature establishes a test-bench kernel with two executable evaluation surfaces:

1. **Artifact detection** — inspect candidate bytes and caller-established provenance for evidence of
   prompt injection.
2. **Contextual alignment** — inspect the same candidate together with a trusted task and permission
   context, and distinguish an aligned instruction, a conflicting instruction, non-instruction content,
   and an indeterminate result.

The action-boundary and full agent-workflow surfaces identified in the research map remain follow-on
features. This feature records enough taxonomy and provenance for those later experiments, but does not
execute arbitrary tools, run an agent, or generate adaptive attacks.

## Scope boundaries

### In scope

- Immutable, versioned case packs for development and holdout evaluation.
- A versioned taxonomy separating attack technique from delivery vector.
- An in-process adapter for the shipping PLEASE pipeline.
- A bounded subprocess protocol for external detectors and research implementations.
- Exact preservation of raw system output alongside a versioned normalized result.
- Reproducible multi-system runs, comparisons, and per-stratum reports.
- Paired cases whose candidate bytes stay fixed while trusted task or permission context changes.
- Explicit accounting for unsupported cases, abstentions, timeouts, crashes, malformed output, and other
  coverage failures.
- Offline-by-default execution and local-only dataset references compatible with existing licensing rules.

### Out of scope for feature 007

- Executing real email, browser, filesystem, cloud, or MCP actions.
- Deciding whether a proposed tool call is authorized.
- Measuring end-to-end user-task or attacker-objective success in an agent environment.
- An adaptive attacker that changes payloads in response to a defense.
- Reproducing attention- or activation-based papers without their required model instrumentation and
  training artifacts.
- A public leaderboard or a claim that one aggregate score identifies a universally best defense.
- New detection behavior in `please-core`, new built-in rules, or a change to the feature-006 product
  operating point.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 — Compare multiple defenses on one frozen case pack (Priority: P1)

A researcher selects a verified case pack and two or more systems. The bench runs every supported system
over the same case identities and produces an immutable result set that can be reproduced from the pack,
system manifests, and run manifest.

**Why this priority**: without a shared input and run contract, every comparison is vulnerable to dataset,
threshold, configuration, and failure-handling drift. This is the minimum useful test bench.

**Independent Test**: run the shipping PLEASE adapter and a subprocess fixture adapter over one mixed
artifact pack, then reproduce identical normalized outcomes from the saved run manifests.

**Acceptance Scenarios**:

1. **Given** a verified pack and two compatible systems, **When** a run is requested, **Then** each system
   receives the same ordered case identities and the result identifies the exact pack and system versions.
2. **Given** a system that times out or crashes on one case, **When** the run completes, **Then** that case
   remains in the output with a failure status and is never normalized as clean.
3. **Given** an existing output directory, **When** another run targets it, **Then** the bench refuses to
   overwrite it.
4. **Given** identical deterministic inputs and system identities, **When** the run is repeated, **Then**
   normalized semantic results are identical; timing and host telemetry remain separately identifiable.

---

### User Story 2 — Measure whether trusted context changes the right decisions (Priority: P1)

A researcher evaluates the same instruction-shaped text in paired cases: authorized by the caller,
introduced by untrusted content, quoted for analysis, or unrelated to the caller's task. Context-free and
context-aware systems can then be compared without changing the candidate wording.

**Why this priority**: AlignSentinel, Task Shield, and the existing false-positive evidence all point to
task alignment and authority as information that text-only detection cannot recover. Paired cases isolate
that information instead of confounding it with vocabulary.

**Independent Test**: run at least one paired group through the context-free PLEASE adapter and a
context-aware fixture adapter, and show that the report preserves the shared input digest while comparing
the different trusted contexts and expected relations.

**Acceptance Scenarios**:

1. **Given** identical candidate bytes in authorized and unauthorized contexts, **When** evaluated, **Then**
   the cases share a group and input digest but retain distinct caller context identities and labels.
2. **Given** a quoted attack example and a live instruction with similar vocabulary, **When** reported,
   **Then** their instruction relation and presentation context are reported separately.
3. **Given** a context-free system, **When** a contextual case is encountered, **Then** the system may
   evaluate the artifact surface but cannot be credited with a contextual-alignment result it did not
   produce.
4. **Given** missing task or permission information required by a contextual system, **Then** the result is
   indeterminate rather than inferred from candidate text.

---

### User Story 3 — Add an external detector without changing the bench (Priority: P2)

A researcher describes a detector or research implementation with a declarative system manifest and a
versioned subprocess adapter. The bench supplies bounded case requests and captures bounded responses
without adding that detector to the PLEASE dependency graph.

**Why this priority**: the bench exists to compare tools, but each tool has its own runtime and output. A
small process boundary keeps those dependencies out of the shipping product and makes failures observable.

**Independent Test**: register a reference subprocess adapter, run it over artifact and unsupported
contextual cases, and verify capability routing, output validation, deadline enforcement, and raw-output
capture.

**Acceptance Scenarios**:

1. **Given** a valid system manifest, **When** its adapter returns a conforming response, **Then** the raw
   response and normalized result are both retained with the adapter version.
2. **Given** malformed, duplicated, oversized, or case-mismatched output, **Then** the whole case response
   is rejected and recorded as invalid output.
3. **Given** a declared artifact-only system, **When** the pack contains contextual cases, **Then** those
   cases are recorded as unsupported for that surface, not silently dropped or counted as clean.
4. **Given** a hung adapter, **When** its deadline expires, **Then** the process is terminated and the run
   continues with later cases.

---

### User Story 4 — Understand tradeoffs without a misleading aggregate (Priority: P1)

A researcher generates a comparison report that shows effectiveness, benign interruption, coverage, and
cost for each system at the exact operating point it used.

**Why this priority**: an unstratified accuracy number hides source dominance, unsupported surfaces,
failures, and different meanings of confidence. Honest reporting is part of the instrument, not a later
documentation task.

**Independent Test**: report a fixture run containing positives, benign instructions, ambiguous cases,
timeouts, unsupported cases, and paired groups; verify every population remains visible in its own
denominator.

**Acceptance Scenarios**:

1. **Given** a multi-source pack, **When** a report is generated, **Then** effectiveness is reported by
   surface, source, technique, and delivery vector before any optional aggregate.
2. **Given** systems with different thresholds or review authority, **Then** the report displays those
   operating points beside their results and does not call their raw scores equivalent.
3. **Given** a requested reviewer that may release findings, **Then** the report separately counts benign
   interruptions removed and caught attacks released.
4. **Given** timeouts, crashes, invalid output, abstentions, and unsupported cases, **Then** each category is
   reported explicitly and remains reconstructable from row-level results.
5. **Given** related variants, **Then** paired changes and group-level uncertainty are reported without
   treating related rows as independent samples.

---

### User Story 5 — Preserve existing evaluation and product boundaries (Priority: P1)

An existing contributor continues to use the feature-006 evaluation, replay, boundary, and product commands
without opting into the new bench.

**Why this priority**: the frozen 006 behavior is the comparison baseline. A research extension that moves
that baseline or adds dependencies to the shipping scanner defeats its purpose.

**Independent Test**: run the current evaluator tests, offline mechanism gate, product/session parity
tests, workspace dependency guards, and default CLI tests before and after the bench is introduced.

**Acceptance Scenarios**:

1. **Given** an existing `please-eval run`, `report`, `gate`, `replay`, or `boundary` invocation, **Then** it
   retains its existing meaning and output contract unless an explicitly versioned migration is documented.
2. **Given** a default workspace build, **Then** no adapter runtime or new evaluation dependency reaches a
   shipping crate.
3. **Given** a bench case containing instructions that resemble configuration, **Then** those bytes cannot
   change the runner, system manifest, limits, trusted context, or normalization policy.

---

### User Story 6 — Prepare a holdout without learning from its outcomes (Priority: P2)

A researcher freezes a case pack from local or third-party material, proves its relationship to prior
exposure, and verifies it before any selected system runs.

**Why this priority**: a flexible bench makes accidental overfitting easier. The existing exposure and
freeze discipline must become a first-class part of every new comparison.

**Independent Test**: prepare development and holdout packs containing related families and deliberate
duplicates; verify that cross-split families, exposed bytes, changed labels, and tampered assets are
rejected before execution.

**Acceptance Scenarios**:

1. **Given** identical or normalized-equivalent content in exposure history, **Then** a proposed fresh
   holdout rejects it.
2. **Given** two cases from the same declared family on opposite sides of a split, **Then** pack validation
   fails.
3. **Given** third-party text, **Then** the repository stores identifiers, labels, licenses, and digests but
   not redistributable prompt text without explicit license approval.
4. **Given** a completed holdout run, **Then** its case identities are added to exposure history before
   another holdout is prepared.

### Edge Cases

- A case digest matches another case but the labels disagree.
- A normalized duplicate appears under a different source or delivery vector.
- One system supports artifact detection while another requires trusted context.
- A subprocess emits a valid response for the wrong case id, emits two responses, writes unlimited stderr,
  closes stdout early, or exits successfully without a response.
- An adapter returns confidence but no documented threshold or label mapping.
- A system abstains on every case, or reports every case as malicious.
- A case is ambiguous or lacks owner-established permission context.
- A case asset is oversized, missing, changes after verification, is a symbolic link, or is a special file.
- Candidate text contains JSONL delimiters, terminal escapes, forged result objects, or instructions aimed at
  the runner.
- A remote-capable adapter is selected while network access is disabled.
- A run label is reused after the pack, adapter, model, prompt, threshold, or normalization recipe changes.
- Multiple repetitions disagree even though the system declared itself deterministic.
- One related family contributes many variants and would dominate row-level confidence intervals.

---

## Requirements *(mandatory)*

### Case packs and labels

- **FR-701**: Every case pack MUST have a schema version, stable pack id, version, content digest, creation
  provenance, license summary, and declared development or holdout purpose.
- **FR-702**: Every case MUST identify exact candidate bytes by SHA-256 and record a stable case id, surface,
  source, caller-established provenance, label, group id, split, delivery vector, and zero or more techniques.
- **FR-703**: Technique and delivery vector MUST be separate versioned fields. For example, credential
  solicitation delivered through an MCP tool description is not an `mcp` detection class.
- **FR-704**: Labels MUST include an explicit ambiguous or indeterminate state. Ambiguous cases MUST remain
  visible but MUST NOT enter binary effectiveness denominators.
- **FR-705**: Contextual cases MUST identify trusted task and typed permission context separately from the
  untrusted candidate. Candidate contents MUST NOT establish their own provenance, permissions, or label.
- **FR-706**: Paired-context cases MUST preserve an identical candidate digest and group id while recording
  distinct trusted-context identities and expected instruction relations.
- **FR-707**: Exact, normalized, and declared-family leakage across development and holdout splits MUST be
  rejected before a pack is frozen.
- **FR-708**: A frozen pack MUST be immutable and independently checkable. Missing, changed, relabeled, or
  extra assets MUST fail verification before any system runs.
- **FR-709**: Third-party text MUST remain outside the repository unless redistribution is explicitly
  permitted. Committed manifests MUST retain enough identity and attribution to verify local bytes.
- **FR-710**: Exposure history MUST be an input to holdout preparation and MUST record every pack used for
  detector selection, tuning, reporting, or final evaluation.

### Evaluation surfaces

- **FR-711**: The artifact-detection request MUST contain bounded candidate bytes, their identity, and
  caller-established provenance; it MUST NOT require task context.
- **FR-712**: The contextual-alignment request MUST additionally contain a trusted task and permission
  context and MUST support the normalized relations `aligned_instruction`, `conflicting_instruction`,
  `non_instruction`, and `indeterminate`.
- **FR-713**: A system MUST declare supported surfaces and required context before a run. Unsupported cases
  MUST be recorded, not dropped and not treated as clean.
- **FR-714**: A context-free result MUST NOT be promoted into a contextual-alignment result by the bench.
  Any derived mapping MUST be a separately named and versioned normalizer.

### Systems and adapters

- **FR-720**: Every system under test MUST have a declarative manifest recording a stable id, version,
  adapter kind and version, supported surfaces, configuration identity, operating threshold, review
  authority, and any model, prompt, rule-set, or executable identities available.
- **FR-721**: The bench MUST provide an in-process adapter for the shipping `please-scan::ScanSession` and
  MUST record whether structural, ML, and judge tiers were requested.
- **FR-722**: The bench MUST provide a versioned JSONL subprocess protocol for external systems without
  linking their dependencies into PLEASE.
- **FR-723**: Adapter responses MUST be matched to a host-issued opaque case id and validated as one complete
  response. Duplicate, missing, mismatched, unknown, or oversized fields MUST reject the response.
- **FR-724**: Raw stdout, bounded stderr, exit status, and adapter diagnostics MUST be retained separately
  from normalized evidence and decisions.
- **FR-725**: Normalizers MUST be independently versioned and identified. A system's native confidence,
  severity, labels, and evidence MUST remain available without being rewritten into PLEASE terminology.
- **FR-726**: Network-capable adapters MUST be declared and explicitly enabled per run. The default bench
  execution MUST make no network request.

### Execution and failure semantics

- **FR-730**: A run manifest MUST bind the pack digest, ordered case identities, system manifests,
  normalizers, limits, repetitions, execution mode, and host/runtime metadata before execution begins.
- **FR-731**: Inputs and results MUST be processed incrementally. The runner MUST NOT retain the entire
  corpus or all raw system outputs in memory.
- **FR-732**: Every case execution MUST have explicit input, stdout, stderr, and elapsed-time limits. A limit
  hit MUST be recorded as incomplete coverage and MUST NOT become a clean result.
- **FR-733**: Case assets MUST be verified as regular files before they are opened. Symbolic links, devices,
  sockets, named pipes, changed files, and other special targets MUST be refused without blocking.
- **FR-734**: Subprocesses MUST run in a fresh run-owned working directory with a minimal allow-listed
  environment. Host credentials and unrelated environment variables MUST NOT be inherited by default.
- **FR-735**: A timeout, crash, signal, spawn failure, malformed response, or unavailable requested tier MUST
  remain a row-level failure. The runner MUST continue when safe and MUST never infer a negative result.
- **FR-736**: Output directories MUST be new and results append-only during a run. Partial runs MUST be
  visibly incomplete and distinguishable from completed runs.
- **FR-737**: Case scheduling MUST be deterministic. Concurrency, warmup, repetitions, and retry policy MUST
  be explicit run settings rather than adapter-controlled behavior.
- **FR-738**: Untrusted candidate bytes and adapter output MUST be escaped or encoded before appearing in
  terminal output, Markdown, logs, or JSON envelopes so they cannot forge bench records.

### Results, comparison, and reporting

- **FR-740**: Each row MUST retain ground truth, raw system output identity, normalized observations,
  normalized decision, coverage state, and execution telemetry as distinct fields.
- **FR-741**: Detector confidence, calibration, assessed impact, and caller enforcement decision MUST remain
  separate quantities. The bench MUST NOT manufacture a common severity from incomparable native scores.
- **FR-742**: Row and evidence identities MUST be stable across deterministic replays and MUST prevent a
  result from being applied to another case, context, system, or configuration.
- **FR-743**: Artifact reports MUST include true/false positives and negatives at each system's recorded
  operating point. Contextual reports MUST include the full relation confusion matrix.
- **FR-744**: Reports MUST show failures, abstentions, indeterminate results, and unsupported cases in
  separate counts and denominators. Requested-system failures on positive cases MUST remain visible as
  non-detections as well as failures.
- **FR-745**: Metrics MUST be reported by surface, source, technique, delivery vector, and system. A
  multi-source result MUST NOT be presented only as a bare aggregate.
- **FR-746**: Paired comparisons MUST operate at the case-group level and report direction changes, not only
  differences between independent row percentages.
- **FR-747**: Reports MUST distinguish detection from caller action. For release-capable review, attacks
  released and benign interruptions removed MUST be separate primary outcomes.
- **FR-748**: Latency, peak memory when available, output volume, remote request count, and declared monetary
  cost MUST be reported separately from effectiveness.
- **FR-749**: Comparison MUST fail closed when pack, label, system, normalizer, or operating-point identities
  are missing or incompatible. Historical unrecorded results may be displayed but not silently compared.

### Compatibility and dependency boundaries

- **FR-760**: Existing evaluator commands and feature-006 run semantics MUST remain unchanged unless an
  explicit versioned migration is documented and regression-tested.
- **FR-761**: Test-bench code and dependencies MUST remain inside the excluded evaluation package. No new
  dependency edge may reach `please-core`, `please-scan`, `please-cli`, `please-judge`, or `please-ml` merely
  because the bench exists.
- **FR-762**: Feature 007 MUST NOT change built-in rules, model defaults, review prompts, scan profiles,
  decision thresholds, or other frozen feature-006 product behavior.
- **FR-763**: CI MUST validate schemas, pack integrity, deterministic fixture adapters, failure behavior,
  report stratification, dependency isolation, and compatibility with the existing offline evaluation gate.
- **FR-764**: Real models, remote judges, gated datasets, and third-party tools MUST remain explicit manual
  evaluations. CI fixtures MUST prove the instrument without making an external-service accuracy claim.

### Key Entities

- **CasePack**: Immutable collection of cases, assets, taxonomy version, split constraints, provenance,
  licensing metadata, exposure evidence, and a digest covering the complete package.
- **BenchCase**: One exact candidate plus ground truth, surface, provenance, group/split membership,
  techniques, delivery vector, and optional trusted caller context.
- **TrustedContext**: Host-owned task and typed permission information used by contextual systems. Its
  identity is reportable even when its text is withheld.
- **SystemUnderTest**: One detector or defense at one frozen configuration and operating point.
- **Adapter**: Versioned boundary that invokes a system and returns its native response. The adapter does
  not assign ground truth.
- **Normalizer**: Versioned mapping from a native response into surface-specific common fields while
  retaining the raw response.
- **ExperimentRun**: Immutable binding of a case pack, systems, limits, scheduling, environment, and output.
- **BenchResult**: Row-level ground truth, native response, normalized result, coverage, and telemetry.
- **ComparisonReport**: Reproducible stratified metrics and paired changes derived from compatible results.
- **ExposureRecord**: Evidence that bytes, normalized content, a family, or a pack have previously influenced
  development or reporting and therefore cannot be called untouched holdout material.

---

## Success Criteria *(mandatory)*

- **SC-701**: One command runs at least two materially distinct system configurations over one verified pack
  and produces complete row-level results and a comparison report bound to exact pack and system digests.
- **SC-702**: Replaying a deterministic fixture experiment produces identical normalized semantic results;
  comparison against itself reports zero changed decisions.
- **SC-703**: Pack checks reject every tested form of tampering, relabeling, duplicate leakage, family
  leakage, missing exposure evidence, and post-verification asset replacement before a system executes.
- **SC-704**: Fixture adapters that hang, crash, emit malformed or oversized output, target the wrong case,
  or return nothing are terminated or rejected within the configured bound; every affected row remains
  explicitly incomplete and later cases still run.
- **SC-705**: A paired-context development pilot contains at least 30 groups across at least three delivery
  vectors, with candidate bytes held constant inside each group and aligned, conflicting, and
  non-instruction controls represented.
- **SC-706**: The contextual report shows the full four-way relation matrix and paired direction changes.
  A context-free system receives no contextual credit from a derived guess.
- **SC-707**: Every multi-source report presents source-, technique-, vector-, and surface-level metrics,
  coverage failures, and operating points before any optional aggregate.
- **SC-708**: A 10,000-case synthetic instrument test processes inputs and writes row results incrementally;
  an instrumented assertion proves the runner retains no more than the configured in-flight cases and does
  not buffer completed raw outputs until the end.
- **SC-709**: A subprocess fixture receives only its declared case request and allow-listed environment; a
  canary credential in the parent environment appears in neither child environment nor any bench output.
- **SC-710**: All pre-feature evaluator tests and the offline mechanism gate pass without baseline edits,
  and the shipping workspace's dependency graphs and default scan outputs are unchanged.
- **SC-711**: The first external-tool comparison identifies its tool version, adapter, model/prompt/rule
  configuration, threshold, supported surfaces, failures, and cost. Any unavailable identity is labeled
  unavailable rather than inferred.
- **SC-712**: No report describes the development pilot, an exposed dataset, or a same-author fixture pack
  as deployment accuracy or an independent holdout.

## Assumptions

- The existing `crates/eval` capture, freeze, replay, product-mode, boundary, exposure, and reporting code is
  the starting point and will be extended rather than replaced wholesale.
- The shipping feature-006 behavior at merge commit `7bec2b3` is the baseline for compatibility checks.
- The first supported host is Linux, including Ubuntu under WSL and Ubuntu CI. Native Windows process
  isolation is deferred until its semantics can be made equivalent and tested.
- The subprocess protocol is the universal external boundary for this feature. In-process adapters are an
  optimization for repository-owned systems, not a requirement imposed on third parties.
- External systems may be nondeterministic. The bench records repetitions and disagreement rather than
  pretending reproducibility of the system itself.
- Dataset labels are claims with provenance, not universal truth. Upstream attack labels do not establish a
  real application's permissions, which is why contextual cases require caller-owned context.
- The 600-case September 11 dataset and current boundary corpus are development/exposed material. They may
  test the instrument but cannot serve as the final untouched holdout for feature 007.
- AlignSentinel's three-way framing motivates the contextual surface; feature 007 does not claim to
  reproduce its attention-based classifier. Attention Tracker, TaskTracker, DataSentinel, and other
  model-internal methods require later adapters when code and compatible runtimes are available.
- Action-boundary evaluation, AgentDojo-like tool simulation, and adaptive attacks are expected follow-on
  features after the two-surface bench proves its contracts.
