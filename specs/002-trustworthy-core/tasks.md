---

description: "Task list for Trustworthy Core — Rule Preparation & Verdict Finalization"
---

# Tasks: Trustworthy Core — Rule Preparation & Verdict Finalization

**Input**: Design documents from `/specs/002-trustworthy-core/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md),
[data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)

**Tests**: Mandatory. The constitution requires security-relevant behaviour to be expressed as failing tests
first, and this feature adds a category the project has not had: a **compile-fail** test, because FR-121 and
SC-108 assert what code *cannot* be written and no test that compiles can verify that.

**Two behaviour changes, isolated.** US1 (validation enforcement) and US2 (class removal) change what the tool
does. Every other phase is behaviour-preserving. They are separate phases and must be separate commits, because
they fail differently and bisecting a regression across a commit that did both would be miserable.

**T001 must run before any other task.** SC-113 pins accuracy unchanged in either direction, and that is only
checkable against a baseline captured before the first edit.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: US1–US5 per [spec.md](./spec.md)
- Exact file paths in every task

---

## Phase 1: Setup

**Purpose**: Capture the baselines this feature is measured against, and the harness for the new test category

- [x] T001 Capture the accuracy baseline — run the fixture report and record per-context, per-difficulty, and false-positive counts verbatim in `docs/002-accuracy-baseline.txt`. **Must be the first task**: SC-113 is uncheckable without it
- [x] T002 Capture the test inventory — record every test name and the total count in `docs/002-test-inventory-before.txt`, so SC-112 can prove no test silently disappeared
- [x] T003 [P] Record the current resolved dependency set in `docs/002-dependency-baseline.txt`; this feature must not change it
- [x] T004 [P] Add `trybuild` as a dev-dependency in `crates/core/Cargo.toml` and create the compile-fail harness at `crates/core/tests/compile_fail.rs`
- [x] T005 [P] Create empty module skeletons at `crates/core/src/prepare/mod.rs`, `crates/core/src/matcher/mod.rs`, and `crates/core/src/finalize/mod.rs`, declared in `crates/core/src/lib.rs`
- [x] T006 [P] Record the migration order and its rationale in `docs/002-migration.md`, including why sealing constructors is last and why the two behaviour changes are separated

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The finalization module tree and the evidence vocabulary. Behaviour-preserving throughout —
migration steps 1–3 from research P7.

**⚠️ CRITICAL**: Both P1 defects are fixed inside this structure, so none of US1 or US2 can start until this is complete.

- [x] T007 Move `Verdict`, `Reason`, `Incompleteness`, `Span`, `Outcome`, `RiskLevel`, `DetectionClass`, `Transform`, `TargetRef`, `RulesetId`, `EngineId`, and `QuotingContext` from `crates/core/src/verdict.rs` into `crates/core/src/finalize/types.rs`, unchanged
- [x] T008 Change every constructor in `crates/core/src/finalize/types.rs` to `pub(super)`, keeping all accessors public (research P3 — a sibling module cannot be granted construction rights, so the types must live here)
- [x] T009 Re-export the verdict types from `crates/core/src/lib.rs` so embedders name them unchanged, and delete `crates/core/src/verdict.rs`
- [x] T010 [P] Write failing compile-fail cases asserting a detector cannot construct a `Reason`, an `Incompleteness`, or a `Verdict` — **one file per claim** in `crates/core/tests/compile_fail/`, because `rustc` stops at the first name-resolution error and a combined case passes for the wrong reason (SC-108)
- [x] T011 Define `Observation` — rule id, one class, span, matched content, severity, chain — in `crates/core/src/finalize/evidence.rs` per [data-model.md](./data-model.md)
- [x] T012 Define `CoverageGap` with the shared cause vocabulary, replacing the four detector-specific shapes, in `crates/core/src/finalize/evidence.rs`
- [x] T013 Define the `Evidence` accumulator with **write-only** record operations for detectors and read access restricted to finalization, in `crates/core/src/finalize/evidence.rs` (FR-122, FR-124)
- [x] T014 Define `ScanPlan` resolving active classes, participating rules, and bounds **once**, in `crates/core/src/finalize/plan.rs` (FR-129)
- [x] T015 Move score aggregation and banding from `crates/core/src/score.rs` to `crates/core/src/finalize/score.rs`
- [x] T016 Move the verdict-assembly logic into `crates/core/src/finalize/mod.rs` as the single producer, taking `Evidence` and producing a `Verdict` (FR-120)
- [x] T017 Move the observation-to-reason transition, including excerpt neutralisation, from `crates/core/src/detect/mod.rs` into `crates/core/src/finalize/mod.rs` (FR-126)
- [x] T018 Route the size-gate construction site in `crates/core/src/engine.rs` through finalization instead of building a verdict directly
- [x] T019 Route the main construction site in `crates/core/src/engine.rs` through finalization
- [x] T020 Route the unreadable-target construction site through finalization and delete `VerdictParts` entirely, in `crates/core/src/finalize/types.rs` and `crates/core/src/engine.rs` (FR-120 — three producers become one)
- [x] T021 Replace `Expansion`'s `depth_exceeded` and `fanout_exceeded` with direct gap recording at the point each bound is hit, in `crates/core/src/decode/mod.rs` (FR-123 — the gap judgement leaves the decoder)
- [x] T022 Replace `RuleMatches::saturated` with direct gap recording in `crates/core/src/detect/pattern.rs`
- [x] T023 Replace the excerpt-truncation boolean with direct gap recording at the neutralisation site, in `crates/core/src/finalize/mod.rs` and `crates/core/src/sanitize.rs` (FR-122)
- [x] T024 Move every test from `crates/core/tests/invariants.rs` to `crates/core/tests/finalization.rs`, rewriting them against constructed evidence rather than a constructed verdict, and delete `invariants.rs` — recording the move in `docs/002-test-inventory-before.txt` (SC-112)

**Checkpoint**: One verdict producer, one gap vocabulary, one class resolution. Behaviour unchanged — verify against T001's baseline before proceeding.

---

## Phase 3: User Story 1 — A supplied rule set cannot produce an unsafe engine (Priority: P1) 🎯 DEFECT

**Goal**: No scanning capability exists for caller-supplied rules that have not been proven to compile within
budget, and this does not depend on caller call order.

**Independent Test**: Attempt every public construction path with a resource bomb and assert each fails; attempt
the same paths with a legitimate rule set and assert each succeeds.

**⚠️ BEHAVIOUR CHANGE** — own commit.

### Tests for User Story 1

- [x] T025 [P] [US1] Create `tests/fixtures/rules/bomb.toml` containing a counted-repetition expansion that parses cleanly and exceeds the compiled budget
- [x] T026 [US1] Write failing test enumerating **every** public construction path and asserting none accepts `bomb.toml`, in `crates/core/tests/preparation.rs` (SC-101, SC-102)
- [x] T027 [US1] Write failing test asserting a rule set whose only defective rule is `enabled = false` is still rejected, in `crates/core/tests/preparation.rs` (FR-107)
- [x] T028 [US1] Write failing test asserting the built-in rule set passes compiled validation at default limits, in `crates/core/tests/preparation.rs` — **the check FR-106 requires and that has never existed**
- [x] T029 [US1] Write failing test asserting limits stricter than a validation record force revalidation, in `crates/core/tests/preparation.rs` (FR-108)
- [x] T030 [P] [US1] Write failing test asserting a caller-supplied pattern is compiled exactly once, in `crates/core/tests/preparation.rs` (FR-109, SC-106)
- [x] T031 [P] [US1] Write failing test asserting validation cost is proportional to caller rules rather than to the resolved set, in `crates/core/benches/preparation.rs` (SC-105)
- [x] T032 [P] [US1] Write failing compile-fail case asserting a caller cannot mint built-in provenance, in `crates/core/tests/compile_fail/provenance_cannot_be_forged.rs` (FR-104)

### Implementation for User Story 1

- [x] T033 [US1] Implement `Provenance` as a public type wrapping a private discriminant, with `Builtin` minted only inside preparation, in `crates/core/src/prepare/provenance.rs` (research P1)
- [x] T034 [US1] Add `provenance` to `Rule` and set it at parse time from the source, in `crates/core/src/ruleset/parse.rs` and `crates/core/src/ruleset/mod.rs` (FR-105)
- [x] T035 [US1] Preserve per-rule provenance through resolution, including replacement, in `crates/core/src/ruleset/mod.rs` (FR-105 — this is what makes delta validation possible)
- [x] T036 [US1] Implement `ValidationRecord` carrying the limits validation was performed against, in `crates/core/src/prepare/prepared.rs` (FR-108)
- [x] T037 [US1] Implement `PreparedRuleset` with a private field and constructors that all validate, in `crates/core/src/prepare/prepared.rs` (FR-102, research P2 — newtype rather than type-state)
- [x] T038 [US1] Move the cheap and expensive validation tiers from `crates/core/src/ruleset/validate.rs` into `crates/core/src/prepare/validate.rs`, and make the expensive tier **retain** each compiled pattern rather than discard it (FR-109)
- [x] T039 [US1] Implement delta validation — validate caller-supplied rules only, treating built-in rules under a default-limit record as already covered — in `crates/core/src/prepare/validate.rs` (SC-105)
- [x] T040 [US1] Implement the three preparation entry points (built-in, from source, layered), each validating, in `crates/core/src/prepare/mod.rs` per [contracts/preparation.md](./contracts/preparation.md)
- [x] T041 [US1] Make `Engine` constructible only from a `PreparedRuleset`, and remove `Ruleset::validate_compiled` from the public surface, in `crates/core/src/engine.rs` and `crates/core/src/ruleset/mod.rs` (FR-103)
- [x] T042 [US1] Include provenance and validation state in the rule-set identity digest, in `crates/core/src/prepare/prepared.rs` (FR-111)
- [x] T043 [US1] Add the built-in validation check to `.github/workflows/ci.yml` so FR-106's guarantee is established rather than assumed

**Checkpoint**: A resource bomb cannot produce a scanner by any route. Run quickstart Scenarios 1, 3, 4, 5.

---

## Phase 4: User Story 2 — Every detection class is independently addressable (Priority: P1) 🎯 DEFECT

**Goal**: Selecting a class finds every finding of that class regardless of delivery mechanism.

**Independent Test**: Five classes × {delivered in the clear, delivered encoded} = ten combinations, each
detected when only its class is active.

**⚠️ BEHAVIOUR CHANGE** — own commit, separate from US1.

### Tests for User Story 2

- [ ] T044 [US2] Write failing test covering all ten class × delivery combinations, in `crates/core/tests/classes.rs` (SC-103)
- [ ] T045 [P] [US2] Write failing test asserting deselecting a class does not affect findings of other classes, in `crates/core/tests/classes.rs` (FR-134)
- [ ] T046 [P] [US2] Write failing test asserting a decoded finding carries its rule's class and records the transformation in its chain, in `crates/core/tests/classes.rs` (FR-131, FR-132)
- [ ] T047 [P] [US2] Write failing CLI test asserting `--classes encoding` is now rejected as an unknown value rather than silently accepted, in `crates/cli/tests/cli.rs`

### Implementation for User Story 2

- [ ] T048 [US2] Remove the `Encoding` variant from `DetectionClass` in `crates/core/src/finalize/types.rs`, and from `ALL_CLASSES` in `crates/core/src/policy.rs` (FR-131)
- [ ] T049 [US2] Update the corroboration-bonus slot mapping for five classes in `crates/core/src/finalize/score.rs` — the exhaustive match will fail to compile until it is updated, which is the intended guard
- [ ] T050 [US2] Make decoded observations carry the class declared by the rule that matched, in `crates/core/src/engine.rs` (FR-131)
- [ ] T051 [US2] Apply the active-class filter exactly once, in `ScanPlan`, and remove both existing filter sites from `crates/core/src/engine.rs` (FR-133 — the double gate is the defect)
- [ ] T052 [P] [US2] Remove the `encoding` value from the CLI class enumeration in `crates/cli/src/args.rs`
- [ ] T053 [P] [US2] Update `rules/builtin.toml`'s header comment, which documents six classes
- [ ] T054 [P] [US2] Update `specs/001-structural-detection-cli/contracts/verdict.schema.json` and `data-model.md` to five classes, noting the amendment and its reason

**Checkpoint**: Ten of ten combinations detected. Run quickstart Scenario 2.

---

## Phase 5: User Story 3 — One place decides what a verdict says (Priority: P2)

**Goal**: The transition from evidence to verdict has one owner, and the disciplines it used to depend on
become structural.

**Independent Test**: Construct evidence directly — including combinations a real scan cannot easily produce —
and assert the resulting verdict, with no engine, no rules, and no input.

### Tests for User Story 3

- [ ] T055 [US3] Write failing tests over constructed evidence covering combinations a real scan cannot easily produce: a saturated rule *and* a truncated excerpt *and* a found payload, in `crates/core/tests/finalization.rs`
- [ ] T056 [P] [US3] Write failing test asserting the score reflects every observation when the report is truncated to one, in `crates/core/tests/finalization.rs` (FR-124, SC-109)
- [ ] T057 [P] [US3] Write failing test enumerating verdict producers and reason-ordering definitions, asserting exactly one of each, in `crates/core/tests/seams.rs` (SC-107)

### Implementation for User Story 3

- [ ] T058 [US3] Derive the score from the `Evidence` accumulator and delete the parallel hit collection from `crates/core/src/engine.rs` (FR-124 — the two-collections bug class disappears)
- [ ] T059 [US3] Delete the duplicate reason sort from `crates/core/src/engine.rs`, leaving the single definition in `crates/core/src/finalize/mod.rs` (FR-125)
- [ ] T060 [US3] Make score-and-risk derivation a property of finalization rather than a silent adjustment of caller-supplied values, in `crates/core/src/finalize/mod.rs` (FR-127)
- [ ] T061 [US3] Reduce `Engine::scan` to orchestration — build the plan, run detectors, hand evidence to finalization — in `crates/core/src/engine.rs`
- [ ] T062 [US3] Reduce `crates/core/src/detect/mod.rs` to dispatch, producing observations only (FR-121)
- [ ] T063 [US3] **Verify** the seal in `crates/core/src/finalize/types.rs` still holds after Phases 3–5, and that each compile-fail case in `crates/core/tests/compile_fail/` still fails with the diagnostic its `.stderr` pins. *Amended*: the sealing itself landed in Phase 2 at T008, because T017–T023 are what remove the last construction sites outside finalization and all of them are Phase 2 — see `docs/002-migration.md`

**Checkpoint**: Only finalization can produce a verdict, and the compiler enforces it.

---

## Phase 6: User Story 4 — The effect of quoting suppression is observable (Priority: P3)

**Goal**: A single scan records what suppression hid and why.

**Independent Test**: Scan content with a payload inside a quoting context; assert the verdict records the
suppression and its context without a second run.

### Tests for User Story 4

- [ ] T064 [P] [US4] Write failing test asserting a suppressed observation is retained with its context, in `crates/core/tests/finalization.rs` (FR-128)
- [ ] T065 [P] [US4] Write failing test asserting suppression is reportable from one scan, in `crates/core/tests/scan.rs` (SC-110)

### Implementation for User Story 4

- [ ] T066 [US4] Add suppressions to the `Evidence` accumulator, retaining the observation and the context that suppressed it, in `crates/core/src/finalize/evidence.rs`
- [ ] T067 [US4] Record suppressions rather than discarding them, removing `let _ = suppressed;` from `crates/core/src/engine.rs`
- [ ] T068 [US4] Populate `suppressed_by` on reported reasons — currently always absent — in `crates/core/src/finalize/mod.rs`
- [ ] T069 [US4] Show suppressed observations under `--explain` in `crates/cli/src/render.rs`, so the false-positive investigation has something to read

**Checkpoint**: "What did suppression change here?" is answerable from one verdict.

---

## Phase 7: User Story 5 — Rule identity cannot drift between components (Priority: P3)

**Goal**: No positional rule identifier crosses a seam.

**Independent Test**: Enumerate the interfaces of the components that select, evaluate, and report on rules and
assert no rule position appears.

### Tests for User Story 5

- [ ] T070 [P] [US5] Write failing test enumerating the matcher's interface and asserting no positional identifier is exchanged, in `crates/core/tests/seams.rs` (SC-111)
- [ ] T071 [P] [US5] Write failing test asserting an observation carries a rule identity rather than a position, in `crates/core/tests/seams.rs` (FR-141)

### Implementation for User Story 5

- [ ] T072 [US5] Move `crates/core/src/prefilter.rs` to `crates/core/src/matcher/prefilter.rs` and make it private to the matcher
- [ ] T073 [US5] Move `crates/core/src/detect/pattern.rs` to `crates/core/src/matcher/patterns.rs` and make it private to the matcher
- [ ] T074 [US5] Have the matcher own the rule slice, the prefilter, and the compiled-pattern slots, exposing an interface that yields observations carrying a rule reference, in `crates/core/src/matcher/mod.rs` (FR-140)
- [ ] T075 [US5] Accept pre-filled compiled patterns from preparation into the matcher's slots, in `crates/core/src/matcher/patterns.rs` (FR-109, research P5)
- [ ] T076 [US5] Remove index-based rule access from `crates/core/src/engine.rs`

**Checkpoint**: The rule position space is unobservable outside one module.

---

## Phase 8: Polish & Amendments

- [ ] T077 Amend FR-024 in `specs/001-structural-detection-cli/spec.md` to require rule-set resource limits (FR-150) — carried over from 001 and still open
- [ ] T077a Record the **`plz --rules` gap** found at the Phase 3 checkpoint: quickstart Scenario 1 and 4 both invoke a CLI flag that does not exist, and 001's `ruleset_load.rs` documented it as already working. US1's guarantee is established at the library level across all seven construction paths; the CLI cannot yet load a caller's rule set at all. Amend `specs/001-structural-detection-cli/spec.md` where it implies otherwise, and note the flag as unbuilt in `docs/limits.md`
- [ ] T078 Amend SC-004 in `specs/001-structural-detection-cli/spec.md` to state warm per-scan and cold-start budgets separately (FR-151)
- [ ] T079 [P] Correct `specs/001-structural-detection-cli/contracts/core-api.md` where it no longer matches the implementation, including the cloneability claim and the two-tier validation split (FR-152)
- [ ] T080 [P] Update `docs/limits.md` if any declared gap changed; this feature should add none
- [ ] T081 [P] Update `docs/attribution.md` with this feature's authorship split
- [ ] T082 Verify the dependency set is unchanged against `docs/002-dependency-baseline.txt`
- [ ] T083 Verify no test was silently lost against `docs/002-test-inventory-before.txt`, recording every move (SC-112)
- [ ] T084 Verify accuracy is unchanged against `docs/002-accuracy-baseline.txt` — **any movement is a defect in this feature, not a tuning result** (SC-113)
- [ ] T085 Run the full `specs/002-trustworthy-core/quickstart.md` validation, all ten scenarios
- [ ] T086 Verify every Constitution Check gate in `specs/002-trustworthy-core/plan.md` is discharged by a **passing mechanical check**, and record the commit that discharges each — the lesson from 001, where gates passed on the strength of design intent

---

## Dependencies & Execution Order

### Phase dependencies

- **Setup (Phase 1)**: T001 strictly first. The rest is parallel
- **Foundational (Phase 2)**: depends on Setup — **BLOCKS every user story**, because both P1 defects are fixed inside the structure it creates
- **US1 (Phase 3)**: depends on Foundational. Independent of US2
- **US2 (Phase 4)**: depends on Foundational. Independent of US1, but **must be a separate commit**
- **US3 (Phase 5)**: depends on Foundational. Completes what Phase 2 began
- **US4 (Phase 6)**: depends on Phase 2's `Evidence`
- **US5 (Phase 7)**: depends on Foundational; T075 additionally depends on T038 (retention) from US1
- **Polish (Phase 8)**: T082–T086 depend on everything

### Critical path

```text
T001 → T005 → T007 → T008 → T009 → T013 → T014 → T016
                                                    ↓
                          US1 (defect) → US2 (defect) → US3 → US4 → US5 → verify
```

T007–T009 are the chokepoint: moving the verdict types is what makes every later guarantee expressible, and it
cannot be done incrementally — the types move together or the crate does not compile.

### Within each story

- Fixtures before the tests consuming them
- Tests before implementation, confirmed failing first
- Provenance before delta validation (T033 → T039): you cannot validate only untrusted rules until you can tell which they are
- `Evidence` before anything recording into it (T013 → T021, T022, T023)
- Sealing last (T063), because it breaks every step before it

### Parallel opportunities

- Setup: T003, T004, T005, T006 after T001
- Foundational: T010 parallel with the type moves; T011–T014 parallel once T009 lands
- US1: T025, T030, T031, T032 parallel; T033–T035 serialise on the rule types
- US2: T045, T046, T047 parallel; T052, T053, T054 parallel
- US5: T070, T071 parallel
- Polish: T079, T080, T081 parallel

---

## Implementation Strategy

### Defects first

1. Phase 1 — **capture baselines before touching anything**
2. Phase 2 — Foundational. Verify behaviour unchanged against T001 before continuing
3. Phase 3 — US1. **Commit alone.** A resource bomb now fails to load
4. Phase 4 — US2. **Commit alone.** Class selection now works
5. **STOP and VALIDATE**: quickstart Scenarios 1–5, and confirm accuracy still matches T001

At that point both shipped defects are closed and the remaining phases are pure refactors, which is a good place
to stop if time runs short.

### Then the refactors

6. Phase 5 — US3, finalization ownership completed and sealed
7. Phase 6 — US4, suppression observable
8. Phase 7 — US5, positional coupling removed
9. Phase 8 — amendments and verification

### Why this order rather than spec priority order

US3 is the largest piece of work and sits at P2 because the two P1 stories are **defects in shipped behaviour**
while US3 improves structure. Closing a reproducible bug outranks concentrating a transition, even when the
transition is bigger and even though the bug fixes depend on some of the transition's groundwork — which is why
that groundwork is Foundational rather than part of US3.

---

## Traceability

| Requirement | Tasks |
|---|---|
| FR-101 preparation owns the transition | T037, T038, T040 |
| FR-102 no capability from unvalidated rules | T026, T037, T041 |
| FR-103 independent of call order | T041 |
| FR-104 provenance unforgeable | T032, T033 |
| FR-105 provenance survives resolution | T034, T035 |
| FR-106 built-in validity established in CI | T028, T043 |
| FR-107 disabled rules validated | T027, T038 |
| FR-108 limits bound to the record | T029, T036 |
| FR-109 compiled work retained | T030, T038, T075 |
| FR-110 suppression needs no compiled validation | T039 |
| FR-111 identity covers trust | T042 |
| FR-120 one verdict producer | T016, T018, T019, T020, T057 |
| FR-121 detectors emit observations only | T010, T062, T063 |
| FR-122 one gap vocabulary | T012, T021, T022, T023 |
| FR-123 gap judgement leaves the decoder | T021 |
| FR-124 aggregate-before-truncate structural | T013, T056, T058 |
| FR-125 one ordering definition | T059, T057 |
| FR-126 observation → reason in finalization | T017 |
| FR-127 no silent score adjustment | T060 |
| FR-128 suppression retained | T064, T066, T067 |
| FR-129 plan resolves classes once | T014, T051 |
| FR-130–FR-132 classes name findings, not delivery | T046, T048, T050 |
| FR-133 filter applied once | T051 |
| FR-134 selection independence | T044, T045 |
| FR-135 decoding disabled by depth bound | T044 |
| FR-140, FR-141 no positional identifier | T070, T071, T072, T073, T074, T076 |
| FR-150–FR-152 amendments | T077, T078, T079 |
| SC-101, SC-102 | T026 |
| SC-103 | T044 |
| SC-104 cold start | T085 |
| SC-105 delta cost | T031, T039 |
| SC-106 no double compile | T030, T038 |
| SC-107 one producer, one order | T057 |
| SC-108 detector cannot construct | T010, T063 |
| SC-109 score structural | T056, T058 |
| SC-110 suppression observable | T065, T069 |
| SC-111 no position exchanged | T070 |
| SC-112 no test lost | T002, T024, T083 |
| SC-113 accuracy unchanged | T001, T084 |

---

## Notes

- **86 tasks.** Two of the eight phases change behaviour; the rest are structural
- **T001 first, T084 last.** Between them, accuracy must not move. A refactor that accidentally *improves*
  detection is as much a defect as one that degrades it — it destroys the baseline the next iteration needs and
  produces a change nobody can safely revert
- **T028 and T043 add a check that has never existed.** The built-in fast path's safety currently rests on
  nothing; these two tasks are the cheapest in the feature and the ones that make the rest coherent
- **T049 will fail to compile before it is done.** Removing a `DetectionClass` variant breaks the exhaustive
  match in scoring, which is the guard 001 deliberately built by refusing a wildcard arm. It working as intended
  here is the payoff
- **T086 is the lesson from 001.** Its gates passed on the strength of design intent, and two of them were false.
  Every gate now names a mechanism and needs a passing check plus the commit that discharges it
- Commit after each task or logical group; agent-authored commits carry the co-author trailer
- Confirm each test fails before implementing. A test that passes on first write is testing something other than
  what it claims
