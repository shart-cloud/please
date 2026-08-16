---

description: "Task list for the judgement tier"
---

# Tasks: The judgement tier

**Input**: Design documents from `/specs/004-judgement-tier/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md),
[data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)

---

## Orientation for a fresh session

Read this before the tasks; it is the context that is not in the design documents.

**Where the project is.** Features 001–003 are shipped. Current accuracy over the fixture corpus: **31/41
positives, 1 false positive** over 17 benign cases. The one remaining false positive is `benign-tool-001`, a
shell transcript displaying payloads from a fixture file. Ten positives remain missed. Both residues need
intent rather than form, which is why this tier exists.

**The four constraints that shape everything.** Do not weaken any of them; each is enforced by a check.

| | |
|---|---|
| `ci/check-core-isolation.sh` | no network, filesystem, subprocess or clock in `crates/core/src` |
| `ci/check-dependencies.sh` | `please-core`'s shipping graph is exactly 27 crates |
| `wasm32-unknown-unknown` | core must keep building for a target with no sockets |
| `cargo clippy --workspace --all-targets -- -D warnings` | clean, always |

**One thing the task breakdown discovered that the design docs do not yet say.** Since 002, `Verdict::new` is
`pub(super)` to `crate::finalize` — **the judge cannot construct a `Verdict`**. So `Judge::review` cannot
rebuild one directly. The resolution is T010: core gains `finalize::rejudge(verdict, decisions) -> Verdict`,
and finalization stays the only producer (002 FR-120). The judge supplies decisions; it does not assemble
verdicts. This is better than the alternative and preserves a guarantee 002 spent a phase establishing.

**Working conventions in this repository**: commit per task or logical group; agent commits carry the
co-author trailer; confirm a test fails before implementing it; never let a credential reach any output.

---

## Format: `[ID] [P?] [Story] Description`

- **[P]**: can run in parallel (different files, no dependency on incomplete work)
- **[Story]**: US1–US5 per [spec.md](./spec.md)
- Exact file paths in every task

---

## Phase 1: Setup

**Purpose**: the crate, and the gate that must exist *before* the dependency does.

- [ ] T001 Capture the accuracy baseline — run the fixture report and record positives, false positives, and
      the missed-case ids verbatim in `docs/004-accuracy-baseline.txt`. **First task**: SC-402 requires the
      unjudged path to stay identical, and that is uncheckable without a before
- [ ] T002 Create `crates/judge` (`please-judge`) with `please-core` as its only dependency, added to
      `members` in the root `Cargo.toml`. **No HTTP dependency yet** — T003 must land first
- [ ] T003 Write `ci/check-cli-dependencies.sh` asserting the **default** `please-cli` graph contains no HTTP
      or TLS crate, and record the current default graph as its baseline in `ci/cli-dependency-allowlist.txt`
      (FR-419, SC-405). **This is the gap the Constitution Check found**: `check-dependencies.sh` has only
      ever covered core, and that stops being sufficient the moment the CLI has optional capability
- [ ] T004 Add `ureq 3` (`default-features = false`, features `rustls` + `json`), `serde`, `serde_json` to
      `crates/judge/Cargo.toml` per research R1
- [ ] T005 Add the `judge` feature to `crates/cli/Cargo.toml`, gating an optional dependency on
      `please-judge`. Default build unchanged
- [ ] T006 Add `ci/check-cli-dependencies.sh` to `.github/workflows/ci.yml` as its own job, beside the
      existing dependency and isolation gates
- [ ] T007 [P] Verify `cargo tree -p please-core --edges normal` is still an exact 27-crate match and
      `wasm32` still builds. The judge must be invisible to both

**Checkpoint**: the guard exists and passes, the crate compiles, core is untouched.

---

## Phase 2: Foundational (blocking)

**Purpose**: the types that make US2's guarantee structural, and the core seam the judge needs.

**⚠️ Nothing in Phase 3+ may start until this is complete** — every later story depends on a verdict that can
be judged without being reconstructable by the judge.

- [ ] T008 Define `SpanJudgement` with **exactly two variants**, `Confirmed` and `Demoted`, in
      `crates/judge/src/lib.rs`. There is no `Cleared`, `Escalated`, or `Added`, and their absence is what
      makes SC-406 a test of a type rather than of validation code (FR-403)
- [ ] T009 Widen `Reason::suppressed_by` to a `SuppressedBy { Quoting(QuotingContext), Judge }` in
      `crates/core/src/finalize/types.rs`, keeping the accessor public and the constructor `pub(super)`. A
      judge-demoted observation is **not quoted**, and reusing `QuotingContext` would be the `Encoding`
      mistake again — a name that stops describing its members (data-model)
- [ ] T010 Add `finalize::rejudge(verdict, decisions) -> Verdict` in `crates/core/src/finalize/mod.rs`,
      moving demoted observations from `reasons` into `suppressed` and recomputing score, ordering, and
      outcome. **Finalization stays the only verdict producer** (002 FR-120) — see the orientation note
- [ ] T011 Extend `tests/seams.rs::exactly_one_place_constructs_a_verdict` to cover the new entry point, so
      `rejudge` cannot become a second producer
- [ ] T012 Define `JudgeReport` — model id, prompt version, document features, per-span judgements,
      `model_severity` — and attach it to `Verdict` with a public accessor (FR-416)
- [ ] T013 [P] Write a test asserting `model_severity` is read by nothing: grep the crate for the field name
      and assert exactly one write site and no read sites (FR-410)
- [ ] T014 Update `specs/001-structural-detection-cli/contracts/verdict.schema.json` and `data-model.md` for
      the widened `suppressed_by`, recording the amendment beside 002's and 003's

**Checkpoint**: a verdict can be re-judged, only finalization can produce one, and demotion is the strongest
thing a judgement can express.

---

## Phase 3: User Story 2 — A captured judge cannot become a bypass (P1) 🔒

**Goal**: bound what an attacker gains when they succeed at injecting the judge — which the design assumes
will happen.

**Independent Test**: drive `rejudge` with generated adversarial decisions and assert no finding leaves the
verdict and no severity rises.

**Why first**: it is the constraint the rest is built inside. Establishing it before any code can return a
judgement means nothing later has to be audited for it.

- [ ] T015 [US2] Write the failing property test in `crates/judge/tests/adversarial_responses.rs`: over
      generated decision sets including maximally permissive and self-contradictory ones, assert
      `judged.reasons() ∪ judged.suppressed() == structural.reasons() ∪ structural.suppressed()` and
      `max severity judged ≤ max severity structural` (SC-406)
- [ ] T016 [US2] Write the failing test asserting a demoted observation is still present, readable, and
      annotated with the judge as what suppressed it
- [ ] T017 [US2] Make them pass against `finalize::rejudge`
- [ ] T018 [P] [US2] Write the failing compile-fail case asserting the judge crate cannot construct a
      `Verdict`, in `crates/core/tests/compile_fail/judge_cannot_construct_a_verdict.rs`, with its `.stderr`

**Checkpoint**: the bypass is not representable. Everything after this is safe to build.

---

## Phase 4: User Story 4 — Credentials resolve predictably and never leak (P2) 🔑

**Goal**: the operator can see what will be sent where, before anything is sent.

**Independent Test**: every combination of the four variables resolves to the documented choice; no test
output anywhere contains a credential value.

**Why before the P1 stories that remain**: US3 must report *which variables were consulted* when none yields
a credential, so resolution has to exist first. No network is involved in any of it.

- [ ] T019 [US4] Implement the credential newtype in `crates/judge/src/credential.rs` with a hand-written
      `Debug` printing the source and never the value, no `Display`, no serialisation (FR-413)
- [ ] T020 [US4] Write the failing test asserting `{:?}` on a credential cannot emit its value
- [ ] T021 [US4] Implement `Resolution::from_env` — order `ANTHROPIC_AUTH_TOKEN`,
      `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY`, **unconditionally**, plus `ANTHROPIC_BASE_URL` and
      `ANTHROPIC_MODEL` (FR-411, FR-412, plan D3)
- [ ] T022 [P] [US4] Write failing tests over every combination of the four variables, including the live
      case: `ANTHROPIC_AUTH_TOKEN` **and** `ANTHROPIC_API_KEY` both set with a custom base URL, where
      choosing wrong sends an upstream account credential to a third-party host
- [ ] T023 [US4] Implement `plz judge --check` in `crates/cli/src/main.rs`: selected variable, ignored
      variables, resolved endpoint and model, **making no request** (FR-414)
- [ ] T024 [US4] Emit the warning when the endpoint is non-default and `ANTHROPIC_API_KEY` is the only
      credential available (FR-415)
- [ ] T025 [US4] Add the suite-wide credential-leak assertion: run the tests with a canary token in the
      environment and assert it appears in no output (SC-404)

**Checkpoint**: `plz judge --check` explains itself, and nothing anywhere prints a secret.

---

## Phase 5: User Story 3 — An unavailable judge is never a clean verdict (P1) 🚨

**Goal**: every failure mode is `Inconclusive`, never `Clean`.

**Independent Test**: each failure mode against content that would otherwise scan clean.

**Why before US1**: the failure path is the safety net, it needs no endpoint, and building it first means the
happy path is added to something already fail-closed rather than the reverse.

- [ ] T026 [US3] Write failing tests in `crates/judge/tests/fail_closed.rs` for each mode: unreachable
      endpoint, no credential, timeout, HTTP 401, tool-use unsupported, malformed JSON, schema violation,
      unknown `span_id`, missing span (SC-403)
- [ ] T027 [US3] Implement the `TierUnavailable` path — every failure records
      `CoverageGap::failure(TierUnavailable, …)` naming the cause, and nothing else (FR-402). This is the
      variant's **first production call site**; it has existed unused since 001
- [ ] T028 [US3] Implement `Judge::review` as infallible: `Verdict → Verdict`, every failure a coverage gap,
      no `Err` for a caller to `unwrap_or_default()` into something cheerful
- [ ] T029 [US3] Return early without a request when the verdict has no observations (FR-404)
- [ ] T030 [P] [US3] Write the failing CLI test asserting exit code `2` for an unreachable endpoint against
      clean content, using a genuinely unreachable port rather than a mock
- [ ] T031 [P] [US3] Write the failing CLI test asserting `--judge` on a build **without** the feature is
      exit `64`, not a silently ignored flag

**Checkpoint**: the tier fails closed before it can succeed at anything.

---

## Phase 6: User Story 1 — A second opinion on what form cannot settle (P1) 🎯

**Goal**: the discriminating judgement. **This is the criterion the tier exists for.**

**Independent Test**: `benign-tool-001` demoted, `indirect-tool-003` reported.

- [ ] T032 [US1] Implement `JudgeRequest` assembly in `crates/judge/src/request.rs`: neutralised document and
      spans via the existing sanitisation path, opaque span ids, and **no rule id, class, or severity**
      (FR-406, FR-408)
- [ ] T033 [P] [US1] Write the failing test asserting the request contains none of *injection*, *attack*,
      *malicious*, *suspicious*, *risk*, and no rule identity — naming the interesting answer produces it
- [ ] T034 [US1] Implement the tool-use request per [contracts/judge-tier.md](./contracts/judge-tier.md),
      with the tool's input schema being
      [contracts/judge-response.schema.json](./contracts/judge-response.schema.json) (research R2)
- [ ] T035 [US1] Implement schema validation in `crates/judge/src/response.rs`: reject entire on unknown
      field, unknown enum value, unrecognised or missing `span_id` — no partial acceptance (FR-409)
- [ ] T036 [US1] Implement the scoring function in `crates/judge/src/score.rs` mapping `Features` →
      `SpanJudgement` (FR-407). **Keep it trivial and obvious**: `description_of_an_instruction` plus a
      corroborating document field demotes, anything else confirms. Tuning waits for the corpus
- [ ] T037 [US1] Assert `unclear` everywhere demotes nothing — abstention must never be cheaper for an
      attacker than honesty
- [ ] T038 [US1] Wire `--judge` and `--judge-timeout` into `crates/cli/src/args.rs` and `main.rs`, behind the
      feature
- [ ] T039 [US1] Write the discriminating test in `crates/judge/tests/discriminates.rs`: `benign-tool-001`
      demoted to clean, `indirect-tool-003` still reported (SC-401). **Failing this means plan D4 chose the
      wrong axis** — revisit D4 rather than tune T036

**Checkpoint**: the pair the structural tier cannot separate is separated. Run quickstart Scenario 5.

---

## Phase 7: User Story 5 — A judged verdict explains itself (P2) 📖

**Goal**: no unexplained numbers. 002 removed a two-run diff from the false-positive workflow; this must not
put one back.

- [ ] T040 [US5] Render judged observations under `--explain` in `crates/cli/src/render.rs`: the feature
      answers, the derived judgement, and the judge named as what suppressed a demoted finding
- [ ] T041 [US5] Render the model id and prompt version in the verdict footer beside the rule-set identity
- [ ] T042 [P] [US5] Write the failing CLI test asserting a judged verdict under `--explain` shows which
      feature drove each judgement

**Checkpoint**: "why did it do that" is answerable from one verdict.

---

## Phase 8: Polish & verification

- [ ] T043 [P] Write the agreement measurement in `crates/judge/tests/agreement.rs` over at least twenty
      hand-labelled spans, **reported not gated** (SC-407). The number is the deliverable; it is expected to
      be imperfect, and turning it into a threshold now would be 001's provisional band boundaries again
- [ ] T044 [P] Record in `docs/limits.md`: the determinism carve-out (FR-417), that a captured judge and a
      correct judgement produce the same verdict, and that `--no-judge` is what distinguishes them
- [ ] T045 [P] Update `specs/001-structural-detection-cli/contracts/core-api.md` for `finalize::rejudge` and
      the widened `suppressed_by`
- [ ] T046 [P] Update `docs/attribution.md` with this feature's authorship split
- [ ] T047 Verify `--no-judge` reproduces the structural verdict byte-identically (FR-418, SC-402)
- [ ] T048 Verify accuracy against `docs/004-accuracy-baseline.txt` — unjudged must be unchanged: 31/41, 1
      false positive, same case ids
- [ ] T049 Verify cold start for the default path against `SC-004b`'s 25 ms. **Building with
      `--features judge` must not slow an unjudged scan** — if it does, the gating is not working (SC-408)
- [ ] T050 Run all eight scenarios in [quickstart.md](./quickstart.md), recording the result of each in
      `docs/004-validation.md` including any that cannot be run and why
- [ ] T051 Verify every Constitution Check gate in [plan.md](./plan.md) is discharged by a **passing
      mechanical check**, recording the commit for each. The four that went in `AT RISK`/`GAP` are the ones
      to look hardest at

---

## Dependencies & execution order

### Phase dependencies

- **Setup (1)**: T003 before T004/T005 — the guard must exist before the dependency it guards against
- **Foundational (2)**: depends on Setup. **Blocks every story**
- **US2 (3)**: depends on Foundational. Blocks nothing but should be first — it is the constraint the rest is
  built inside
- **US4 (4)**: depends on Foundational. Needed by US3 (reporting which variables were consulted) and US1
  (making a request)
- **US3 (5)**: depends on US4
- **US1 (6)**: depends on US3 and US4. The only story needing a reachable endpoint
- **US5 (7)**: depends on US1
- **Polish (8)**: T047–T051 depend on everything

### Critical path

```text
T001 → T003 → T005 → T008 → T009 → T010 → T012
                                              ↓
                     US2 (bypass) → US4 (auth) → US3 (fail-closed) → US1 (judge) → US5 → verify
```

T009 and T010 are the chokepoint: widening `suppressed_by` and adding `rejudge` are what make a judged verdict
expressible at all, and they touch `please-core`, so they land together or the crate does not compile.

### Why this order rather than spec priority order

Three stories are P1 and one P2 sits among them, which looks wrong and is not.

**US2 first** because it is a constraint rather than a capability. Establishing that demotion is the strongest
expressible judgement *before* any code can produce one means nothing later needs auditing for it.

**US4 before the remaining P1s** because US3 must report which variables it consulted when none yields a
credential, and US1 cannot make a request without one. It is P2 by user-visible value and a prerequisite by
dependency.

**US3 before US1** because the failure path is the safety net and needs no endpoint. Building it first means
the happy path is added to something already fail-closed, rather than fail-closed being retrofitted to
something that works.

**US1 last among the P1s** because it is the only story that cannot be tested offline.

### Parallel opportunities

- Setup: T007 alongside T004–T006
- Foundational: T013 alongside T009–T012
- US2: T018 parallel with T015–T017
- US4: T022 parallel with T019–T021
- US3: T030 and T031 parallel
- US1: T033 parallel with T032
- Polish: T043–T046 all parallel

---

## Implementation strategy

1. **Phase 1–2 first, and do not skip T003.** The dependency guard is the gap the Constitution Check found;
   adding the HTTP dependency before the check exists is how the gap becomes permanent.
2. **Phase 3 (US2).** After this, a bug in the judge cannot cost a finding.
3. **Phases 4–5 (US4, US3).** Everything offline. **A good place to stop if time runs short** — at this point
   the tier exists, fails closed, and explains its configuration, without yet being able to reach anything.
4. **Phase 6 (US1).** Needs an endpoint. The moment of truth is T039.
5. **Phases 7–8.**

### If T039 fails

Do not tune T036. A failing discriminating test means the axis in plan D4 — *instructing versus displaying* —
was the wrong question, and the response is to revisit D4 with what the failure showed. Tuning the scoring
function to pass two fixtures would produce a tier that passes two fixtures.

---

## Traceability

| Requirement | Tasks |
|---|---|
| FR-401 separate crate, opt-in | T002, T005, T038 |
| FR-402 unavailable → inconclusive | T026, T027 |
| FR-403 confirm or demote only | T008, T015, T017 |
| FR-404 no observations, no request | T029 |
| FR-405 closed enums, no free text | T034, T035 |
| FR-406 no leading words, no rule ids | T032, T033 |
| FR-407 score computed here | T036 |
| FR-408 content neutralised | T032 |
| FR-409 reject entire | T035 |
| FR-410 `model_severity` unread | T012, T013 |
| FR-411–412 resolution order and overrides | T021, T022 |
| FR-413 no credential in output | T019, T020, T025 |
| FR-414 diagnostic without a request | T023 |
| FR-415 non-default host warning | T024 |
| FR-416 model id and prompt version | T012, T041 |
| FR-417 determinism carve-out | T044 |
| FR-418 `--no-judge` reproduces structural | T047 |
| FR-419 CLI dependency gate | T003, T006 |
| FR-420 timeout | T038 |
| SC-401 discriminating pair | T039 |
| SC-402 unjudged unchanged | T001, T047, T048 |
| SC-403 every failure inconclusive | T026, T030 |
| SC-404 no credential in any output | T025 |
| SC-405 default build has no HTTP crate | T003, T006 |
| SC-406 adversarial property | T015, T018 |
| SC-407 agreement measured | T043 |
| SC-408 cold start | T049 |

---

## Notes

- **51 tasks.** Roughly half need no network and no credential, which is where the security properties live
- **T003 is the cheapest task with the most leverage.** It closes a gap that has been open since the CLI
  existed, and it must land before the dependency it guards
- **T010 preserves 002's central guarantee.** The judge supplies decisions; finalization stays the only thing
  that can produce a verdict. Discovered during this breakdown and not yet reflected in `data-model.md` —
  worth an amendment when T010 lands
- **T039 is the feature.** Everything else is scaffolding around whether that one test can pass
- Confirm each test fails before implementing. A test that passes on first write is testing something other
  than what it claims
