---

description: "Task list for Structural Detection & Scan CLI"
---

# Tasks: Structural Detection & Scan CLI

**Input**: Design documents from `/specs/001-structural-detection-cli/`

**Prerequisites**: [plan.md](./plan.md), [spec.md](./spec.md), [research.md](./research.md),
[data-model.md](./data-model.md), [contracts/](./contracts/), [quickstart.md](./quickstart.md)

**Tests**: Test tasks are **included and mandatory**. The constitution requires detection behaviour to
be expressed as failing tests before implementation, and requires property-based and fuzz coverage of
the analysis bounds. Tests here are not optional additions.

**Regenerated 2026-08-15** against the clarified spec (36 FR, 13 SC) and the second-pass design. Changes
from the first list: `LimitHit` became `Incompleteness`, `EngineId` and `QuotingContext` gained defining
tasks, and new tasks cover FR-020, FR-031, FR-032a, SC-001a, the score-aggregation formula, the
scheduled fuzz campaign, and concurrent-scan safety.

**Organization**: Grouped by user story so each is independently implementable and testable.

## Format: `[ID] [P?] [Story] Description`

- **[P]**: Can run in parallel (different files, no dependencies)
- **[Story]**: Which user story this task belongs to (US1–US4)
- Exact file paths are given in every task

## Path Conventions

Rust workspace per [plan.md](./plan.md): `crates/core/` (`please-core`), `crates/cli/` (`please-cli`,
binary `plz`), `crates/eval/` excluded from the workspace. Shared fixtures and the dependency guard at
repository root under `tests/`.

---

## Phase 1: Setup (Shared Infrastructure)

**Purpose**: Workspace, toolchain, and CI skeleton

- [x] T001 Create workspace manifest at `Cargo.toml` with members `crates/core` and `crates/cli`, and `exclude = ["crates/eval"]`, plus shared `[workspace.package]` metadata
- [x] T002 [P] Create `rust-toolchain.toml` pinning the stable channel with `rustfmt` and `clippy` components
- [x] T003 [P] Create `rustfmt.toml` with the project's formatting settings
- [x] T004 Create `crates/core/Cargo.toml` declaring `regex`, `aho-corasick`, `unicode-security`, `unicode-normalization`, `base64`, `toml`, and optional `serde` behind a default-off `serde` feature
- [x] T005 Create `crates/cli/Cargo.toml` declaring `[[bin]] name = "plz"`, `please-core` with the `serde` feature, `clap`, and `serde_json`
- [x] T006 [P] Create `crates/eval/Cargo.toml` as a standalone package outside the workspace, with a placeholder `crates/eval/src/lib.rs` noting that corpus tooling arrives in its own feature
- [x] T007 [P] Create `.github/workflows/ci.yml` with jobs for `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace`
- [x] T008 [P] Create `docs/attribution.md` recording which components are agent-authored and which are human-authored, per the constitution's attribution gate
- [x] T009 [P] Create `docs/limits.md` stating the declared gaps — multilingual detection, the heuristic quoting pre-pass, provisional band calibration, and the structural tier's inability to detect novel phrasing
- [x] T010 Implement fixture-path resolution relative to `CARGO_MANIFEST_DIR` so tests in `crates/core/tests/` can read repository-root fixtures regardless of working directory, in `crates/core/tests/support.rs`

---

## Phase 2: Foundational (Blocking Prerequisites)

**Purpose**: The verdict model, rule-set machinery, scoring, and scan pipeline that every user story builds on

**⚠️ CRITICAL**: No user story work can begin until this phase is complete

- [x] T011 [P] Define `Span`, `RiskLevel`, and `DetectionClass` (six variants, non-exhaustive) in `crates/core/src/verdict.rs`
- [x] T012 Define `Outcome`, `Verdict`, `Reason`, `Incompleteness` (with its nine discriminated causes), `Transform`, `TargetRef`, `EngineId`, and `QuotingContext` in `crates/core/src/verdict.rs` per [data-model.md](./data-model.md) (depends on T011)
- [x] T013 [P] Define `ScanPolicy` with the documented defaults (1 MiB input, depth 3, 16 matches/rule, 64 reasons, 256-byte excerpts, `high` threshold) in `crates/core/src/policy.rs`
- [x] T014 Write failing test asserting `Outcome::Clean` is produced only when `reasons` AND `incomplete` are both empty, in `crates/core/tests/invariants.rs`
- [x] T015 Write failing property test asserting no generated input yields `Clean` when any `Incompleteness` was recorded, in `crates/core/tests/invariants.rs`
- [x] T016 Write failing test asserting outcome precedence `risk_found` > `inconclusive` > `clean`, including the case where a payload is found and a bound is also hit, in `crates/core/tests/invariants.rs`
- [x] T017 Implement `Verdict` assembly enforcing the FR-004 invariant and FR-032b precedence at a single point, in `crates/core/src/verdict.rs` (makes T014–T016 pass)
- [x] T018 [P] Write failing tests for excerpt neutralisation covering C0/C1 controls, bidi overrides, zero-width characters, the Unicode Tags block, and variation selectors, in `crates/core/tests/sanitize.rs`
- [x] T019 Implement excerpt neutralisation and length capping in `crates/core/src/sanitize.rs` (makes T018 pass)
- [x] T020 [P] Define `Rule`, `Ruleset`, and `RulesetId` in `crates/core/src/ruleset/mod.rs` per [contracts/ruleset.md](./contracts/ruleset.md)
- [x] T021 Write failing tests for rule-set rejection — unknown key, malformed id, duplicate id, unknown class, out-of-range severity, uncompilable pattern, look-around usage, oversized pattern source, oversized compiled program, excess rule count — in `crates/core/tests/ruleset_load.rs`
- [x] T022 Implement TOML deserialisation of rule sets in `crates/core/src/ruleset/parse.rs`
- [x] T023 Implement load-time validation with pattern-source, compiled-size, and rule-count limits, rejecting the whole set on any failure, in `crates/core/src/ruleset/validate.rs` (makes T021 pass)
- [x] T024 Implement rule-set resolution (built-in → additions → suppressions) and the content digest over the resolved set in `crates/core/src/ruleset/mod.rs`
- [x] T025 Create `rules/builtin.toml` with the `[ruleset]` header, `[bands]` table, and a comment recording that band boundaries are provisional pending corpus calibration
- [x] T026 Embed `rules/builtin.toml` at compile time and implement `Engine::builtin()`, `Engine::from_toml()`, and `Engine::builder()` in `crates/core/src/lib.rs`
- [x] T027 [P] Implement the multi-literal prefilter over all rules' literals, warning on rules with no literals, in `crates/core/src/prefilter.rs`
- [x] T028 Implement lazy per-rule pattern compilation with a compiled-size limit and memoised caching behind interior synchronisation, in `crates/core/src/detect/pattern.rs`
- [x] T029 Implement bounded match collection capped at `max_matches_per_rule`, recording an `Incompleteness` on saturation, in `crates/core/src/detect/pattern.rs`
- [x] T030 [P] Write failing property tests for the score formula asserting insensitivity to input length, insensitivity to repeated matches of one rule, monotonic increase with distinct classes, and the 100 ceiling, in `crates/core/tests/score.rs`
- [x] T031 Implement score aggregation as `min(100, max_severity + min(15, 5 × (distinct_classes − 1)))`, computed over all matches before reason truncation, plus banding, in `crates/core/src/score.rs` (makes T030 pass)
- [x] T032 Implement `Engine::scan` assembling the pipeline (size gate → decode → structure → prefilter → patterns → suppression → score → verdict), returning `Verdict` and never `Result`, in `crates/core/src/lib.rs`
- [x] T033 [P] Add `#![forbid(unsafe_code)]` and crate-level documentation stating the no-clock, no-filesystem, no-network contract to `crates/core/src/lib.rs`
- [x] T034 [P] Add dependency guard test asserting the default build's resolved dependency set matches a committed allow-list, in `tests/dep_guard.rs`
- [x] T035 [P] Configure a static gate denying networking and filesystem interfaces inside the core crate in `clippy.toml`, and enforce it as a CI job in `.github/workflows/ci.yml`
- [x] T036 [P] Add a `cargo build -p please-core --target wasm32-unknown-unknown` job to `.github/workflows/ci.yml`

**Checkpoint**: Verdict model, rule loading, scoring, and the scan pipeline exist. Detection classes can now be built in parallel.

---

## Phase 3: User Story 1 - Check an artifact before trusting it (Priority: P1) 🎯 MVP

**Goal**: Point the tool at a file and get an actionable verdict — risk level, rule, location, and a
neutralised excerpt — including for payloads invisible to a reader.

**Independent Test**: Scan committed fixtures, one per detection class plus benign controls, and assert
the reported risk level and reasons. No harness, no configuration, no network.

### Tests for User Story 1 ⚠️

> **Write these FIRST and confirm they FAIL before implementing**

- [x] T037 [P] [US1] Create positive fixtures for instruction override in `tests/fixtures/override/` including `ignore_previous.md`
- [x] T038 [P] [US1] Create positive fixtures for concealment in `tests/fixtures/concealment/` including `tag_block_payload.txt`, `zero_width.txt`, and `bidi_reversed.txt`
- [x] T039 [P] [US1] Create positive fixtures for confusables in `tests/fixtures/confusable/` including a Cyrillic-substituted keyword
- [x] T040 [P] [US1] Create positive fixtures for encoding in `tests/fixtures/encoding/` including `base64_override.txt`, `hex_override.txt`, `rot13_override.txt`, `reversed_override.txt`, and `leetspeak_override.txt`
- [x] T041 [P] [US1] Create positive fixtures for boundary forgery in `tests/fixtures/boundary/` including forged role markers and tool-result impersonation
- [x] T042 [P] [US1] Create positive fixtures for solicitation in `tests/fixtures/solicitation/` including system-prompt extraction requests
- [ ] T043 [US1] Create **at least 200** hard-negative fixtures in `tests/fixtures/benign/` including `threat_model_excerpt.md`, advisories discussing injection, `certificate_block.pem`, content-hash listings, non-English prose, and `plain.md` — the 200 minimum is part of SC-003, not a suggestion
- [x] T044 [US1] Write failing per-class detection tests asserting every positive fixture is detected and every benign control is silent, in `crates/core/tests/fixtures.rs` (SC-002)
- [x] T045 [US1] Write failing test asserting the false-positive rate over `tests/fixtures/benign/` is at most 1% at the default threshold, and failing the run if the set holds fewer than 200 examples, in `crates/core/tests/fixtures.rs` (SC-003)
- [x] T046 [US1] Write failing test asserting every `risk_found` verdict carries rule identity, class, location, excerpt, and description, in `crates/core/tests/fixtures.rs` (SC-001, SC-008)
- [x] T047 [P] [US1] Write failing tests asserting an encoded blob whose decoded content matches no rule produces no finding, in `crates/core/tests/decode.rs` (D5)

### Implementation for User Story 1

- [x] T048 [US1] Implement the linear-time structural pre-pass classifying fenced code, inline code, block quotes, quoted strings, and attributive-marker spans, in `crates/core/src/structure.rs`
- [x] T049 [US1] Implement quoting suppression honouring each rule's `fires_in_quotes` and recording the `QuotingContext` that suppressed a match, in `crates/core/src/detect/mod.rs` (depends on T048)
- [x] T050 [P] [US1] Implement the concealment scanner covering C0/C1, U+200B–U+200F, U+2060–U+2064, U+202A–U+202E, U+2066–U+2069, U+FEFF, U+180E, the Tags block U+E0000–U+E007F, and variation selectors, in `crates/core/src/detect/concealment.rs`
- [x] T051 [P] [US1] Implement Tags-block decoding (subtract U+E0000 to recover ASCII) and variation-selector decoding, feeding recovered text back into the decode pipeline, in `crates/core/src/decode/unicode.rs`
- [x] T052 [P] [US1] Implement per-token confusable analysis using UTS #39 skeleton, mixed-script, and restriction level, explicitly not flagging whole-document script mixing, in `crates/core/src/detect/confusable.rs` (D7)
- [x] T053 [P] [US1] Implement the base-64 decoder with charset, length, and decoded-printability gating in `crates/core/src/decode/base64.rs`
- [x] T054 [P] [US1] Implement hexadecimal, rotation-cipher, reversal, and glyph-substitution decoders in `crates/core/src/decode/hex.rs`, `rot13.rs`, `reversed.rs`, and `leetspeak.rs`
- [x] T055 [US1] Implement the bounded, cycle-guarded decode pipeline that re-scans decoded output and reports a transformation only when the decoded content trips a rule, in `crates/core/src/decode/mod.rs` (depends on T051, T053, T054; makes T047 pass)
- [x] T056 [US1] Implement class dispatch wiring pattern, concealment, and confusable detectors into the scan, in `crates/core/src/detect/mod.rs`
- [x] T057 [US1] Author the built-in `override` and `boundary` rules with literals, patterns, severities, and required descriptions in `rules/builtin.toml`
- [x] T058 [US1] Author the built-in `solicitation` rules and the rules that fire on decoded content in `rules/builtin.toml`
- [x] T059 [US1] Implement `Verdict::summary()` and `Verdict::is_at_or_above()` in `crates/core/src/verdict.rs`
- [x] T060 [US1] Implement CLI argument parsing for `plz scan` with target, `--format`, `--threshold`, `--explain`, and the bound overrides, in `crates/cli/src/args.rs`
- [x] T061 [US1] Implement target reading for file paths, `-`/stdin, and lexicographic directory walking, in `crates/cli/src/target.rs`
- [x] T062 [US1] Implement human-readable rendering per [contracts/cli.md](./contracts/cli.md), showing band, score, rule id, byte span, neutralised excerpt, description, decode chain, and the `unexamined:` line, in `crates/cli/src/render/human.rs`
- [x] T063 [US1] Wire `main` to build the engine, scan each target, and render, in `crates/cli/src/main.rs`
- [x] T064 [US1] Add snapshot tests for human output over representative fixtures in `crates/cli/tests/cli.rs`

**Checkpoint**: `plz scan <file>` reports actionable findings for all six classes and stays silent on technical security prose. MVP is demonstrable.

---

## Phase 4: User Story 2 - Gate an agent's tool call automatically (Priority: P2)

**Goal**: A non-interactive contract a hook can branch on — clean machine-readable output on stdout,
diagnostics on stderr, and six distinguishable status codes.

**Independent Test**: Invoke non-interactively against fixtures and assert exact status codes and output
shape, with no human reading the result.

### Tests for User Story 2 ⚠️

- [ ] T065 [P] [US2] Write failing test asserting `--format json` output validates against `specs/001-structural-detection-cli/contracts/verdict.schema.json` for every fixture, in `crates/cli/tests/contract.rs`
- [ ] T066 [P] [US2] Write failing test asserting stdout carries only the result document and all diagnostics go to stderr, in `crates/cli/tests/contract.rs`
- [ ] T067 [P] [US2] Write failing tests asserting all six status codes (0, 1, 2, 3, 64, 70) are reachable and distinct, in `crates/cli/tests/exit_codes.rs`
- [ ] T068 [P] [US2] Write failing determinism test asserting byte-identical `--format json` output across repeated runs and from different working directories, in `crates/cli/tests/determinism.rs` (SC-011)

### Implementation for User Story 2

- [ ] T069 [US2] Implement `serde` derives on the verdict types behind the `serde` feature, using ordered collections and integer scores, in `crates/core/src/verdict.rs`
- [ ] T070 [US2] Implement JSON rendering emitting a single object per target and an array for multiple targets, with no timestamp and no absolutised paths, in `crates/cli/src/render/json.rs` (makes T065, T068 pass)
- [ ] T071 [US2] Implement status-code mapping including the distinct below-threshold code 3 and the sysexits codes 64 and 70, in `crates/cli/src/exit.rs` (makes T067 pass)
- [ ] T072 [US2] Implement stream discipline ensuring warnings and rule-set load errors never reach stdout, in `crates/cli/src/main.rs` (makes T066 pass)
- [ ] T073 [US2] Implement multi-target summary status derived by the `risk_found` > `inconclusive` > `clean` precedence, in `crates/cli/src/main.rs` (FR-032b)
- [ ] T074 [P] [US2] Add the reference pre-tool hook script, routing inconclusive explicitly, to `examples/hooks/pre-tool.sh`
- [ ] T075 [P] [US2] Document the integration contract and copyable hook in `README.md`

**Checkpoint**: A hook can gate on `plz` using only documented status codes and JSON. US1 and US2 both work independently.

---

## Phase 5: User Story 3 - Hostile and oversized input is handled honestly (Priority: P3)

**Goal**: The scanner cannot be made slow or unstable by crafted input, cannot be steered by the content
it scans, and says so rather than reporting clean when it cannot conclude.

**Independent Test**: Drive the scan with adversarial input — at and beyond bounds, deeply nested
encodings, cycles, invalid encodings, unreadable targets — and assert bounded completion, no crashes,
and explicit inconclusive outcomes.

### Tests for User Story 3 ⚠️

- [ ] T076 [P] [US3] Create adversarial fixtures in `tests/fixtures/adversarial/` including `decode_cycle.txt`, `nested_base64_x3.txt`, `invalid_utf8.bin`, pathological repetition, and a single very long line
- [ ] T077 [P] [US3] Create resource-exhausting rule sets in `tests/fixtures/rules/` including `malformed.toml` and a counted-repetition expansion bomb
- [ ] T078 [US3] Write failing property tests asserting every bound (`input_size`, `decode_depth`, `max_matches_per_rule`, `max_reasons`, `excerpt_length`) is enforced and reported as an `Incompleteness`, in `crates/core/tests/bounds.rs`
- [ ] T079 [US3] Write failing test asserting oversized input yields `inconclusive` with cause `input_size` and never `clean`, in `crates/core/tests/bounds.rs` (SC-007)
- [ ] T080 [US3] Write failing test asserting a rule set that fails to load never yields a clean verdict from an empty rule set, in `crates/core/tests/ruleset_load.rs`
- [ ] T081 [P] [US3] Write failing test asserting an input containing text resembling a rule definition, a configuration directive, or an instruction addressed to the scanner produces the same verdict as the same input with that text as inert prose, in `crates/core/tests/no_self_steering.rs` (FR-020a)
- [ ] T082 [P] [US3] Write failing test asserting per-input verdicts are identical regardless of the order inputs were scanned in, and regardless of what was scanned before them, in `crates/core/tests/no_self_steering.rs` (FR-020b)
- [ ] T083 [P] [US3] Write failing test asserting concurrent scans of identical input through one shared engine produce identical verdicts, and that lazy pattern compilation makes no verdict depend on scan history, in `crates/core/tests/concurrency.rs`
- [ ] T084 [P] [US3] Write failing test asserting an unreadable target during a directory walk yields `inconclusive` with cause `target_unreadable`, that the walk continues, and that the summary is inconclusive rather than clean, in `crates/cli/tests/walk.rs` (FR-032a, FR-032b)
- [ ] T085 [P] [US3] Add a fuzz target for the scan entry point in `crates/core/fuzz/fuzz_targets/scan.rs`
- [ ] T086 [P] [US3] Add a fuzz target for the decode pipeline in `crates/core/fuzz/fuzz_targets/decode.rs`
- [ ] T087 [P] [US3] Add a criterion benchmark sweeping input size across four orders of magnitude and asserting the fitted growth exponent stays within tolerance of 1.0, in `crates/core/benches/scaling.rs` (SC-005)

### Implementation for User Story 3

- [ ] T088 [US3] Implement the input size gate short-circuiting to `inconclusive` before any analysis, in `crates/core/src/lib.rs` (makes T079 pass)
- [ ] T089 [US3] Implement decode-depth bounding and cycle detection by hashing visited decoded buffers, recording unexamined remainders, in `crates/core/src/decode/mod.rs`
- [ ] T090 [US3] Implement `max_reasons` truncation setting `reasons_truncated`, and reason ordering by `(span.start, rule_id)`, in `crates/core/src/verdict.rs`
- [ ] T091 [US3] Implement lossless handling of invalid UTF-8 sequences without rejecting the input, in `crates/core/src/lib.rs`
- [ ] T092 [US3] Implement unreadable-target handling in the directory walk, constructing an inconclusive verdict with cause `target_unreadable` and continuing, in `crates/cli/src/target.rs` (makes T084 pass)
- [ ] T093 [US3] Add a throughput benchmark asserting warm p95 within 10 ms at 4 KB and at least 10 MB/s sustained, in `crates/core/benches/scaling.rs` (SC-004)
- [ ] T094 [US3] Add a cold-start measurement of process launch to first verdict, budgeted at 25 ms, in `crates/cli/tests/coldstart.rs` (D4)
- [ ] T095 [P] [US3] Add per-change fuzz smoke and benchmark gate jobs to `.github/workflows/ci.yml`
- [ ] T096 [US3] Add a scheduled fuzz campaign workflow accumulating toward and past one million cumulative inputs, publishing the iteration count and any discovered crashes as run artifacts, in `.github/workflows/fuzz-campaign.yml` (SC-006)

**Checkpoint**: Bounds are enforced and reported, content cannot steer analysis, and linearity is measured rather than asserted.

---

## Phase 6: User Story 4 - Tune and extend detection without a rebuild (Priority: P4)

**Goal**: A team suppresses a built-in rule and adds their own, sees both take effect with no rebuild,
and can attribute any past verdict to the exact rules that produced it.

**Independent Test**: Scan one fixture against two rule sets differing by a single rule and assert the
verdicts differ accordingly; assert the rule-set identity recorded in each verdict.

### Tests for User Story 4 ⚠️

- [ ] T097 [P] [US4] Create `tests/fixtures/rules/acme.toml` with a caller-defined boundary rule, and `tests/fixtures/override/acme_marker.txt` matching it
- [ ] T098 [US4] Write failing test asserting a caller-supplied rule fires and appears in the verdict by its own id, in `crates/core/tests/ruleset_load.rs` (SC-010)
- [ ] T099 [US4] Write failing test asserting a suppressed built-in rule stops matching and the input reports clean, in `crates/core/tests/ruleset_load.rs`
- [ ] T100 [US4] Write failing test asserting the resolved rule-set digest changes when rules are added or suppressed, in `crates/core/tests/ruleset_load.rs` (SC-012)
- [ ] T101 [P] [US4] Write failing test asserting an addition replacing a built-in id is reported at load, and that suppressing an unknown id is a usage error rather than a no-op, in `crates/core/tests/ruleset_load.rs`

### Implementation for User Story 4

- [ ] T102 [US4] Implement `--rules` and repeatable `--disable-rule` argument handling in `crates/cli/src/args.rs`
- [ ] T103 [US4] Implement rule-set file loading in the CLI, keeping filesystem access out of the core, in `crates/cli/src/main.rs`
- [ ] T104 [US4] Implement replacement reporting and unknown-suppression rejection in `crates/core/src/ruleset/mod.rs` (makes T101 pass)
- [ ] T105 [US4] Implement `--classes` selection disabling detection classes independently, in `crates/cli/src/args.rs` and `crates/core/src/detect/mod.rs`
- [ ] T106 [US4] Implement `--no-suppress-in-quotes` surfacing `suppressed_by` on affected reasons, in `crates/cli/src/args.rs` and `crates/core/src/detect/mod.rs`
- [ ] T107 [P] [US4] Document the rule format, resolution order, and the worked override example in `docs/rules.md`

**Checkpoint**: All four user stories independently functional.

---

## Phase 7: Polish & Cross-Cutting Concerns

- [ ] T108 Amend FR-024 in `specs/001-structural-detection-cli/spec.md` to require rule-set resource limits — a resource-exhausting rule is well-formed, so T023 currently implements a constraint the spec does not ask for
- [ ] T109 [P] Pin the minimum supported Rust version in `Cargo.toml` from the actual floor of the resolved dependency set, and assert it in `.github/workflows/ci.yml`
- [ ] T110 [P] Write `README.md` covering purpose, install, and the scan contract, stating explicitly that accuracy is fixture-verified and **not** yet corpus-measured
- [ ] T111 [P] Complete `docs/limits.md` with every declared gap and the reason each exists
- [ ] T112 [P] Complete `docs/attribution.md` with the final agent- versus human-authored component breakdown
- [ ] T113 Add rustdoc to every public item in `crates/core/src/`, including the invariant that `Clean` requires both accumulators empty
- [ ] T114 Define the per-release comprehension walkthrough procedure and record its first result, with reader name and date, in `docs/walkthrough-log.md` (SC-001a)
- [ ] T115 Run the full `specs/001-structural-detection-cli/quickstart.md` validation, all eight scenarios, and record results
- [ ] T116 Verify every Constitution Check gate in `specs/001-structural-detection-cli/plan.md` is discharged by a passing mechanical check, and record the commit that discharges each

---

## Dependencies & Execution Order

### Phase Dependencies

- **Setup (Phase 1)**: No dependencies
- **Foundational (Phase 2)**: Depends on Setup — **BLOCKS all user stories**
- **US1 (Phase 3)**: Depends on Foundational. No dependency on other stories
- **US2 (Phase 4)**: Depends on Foundational. Renders verdicts US1 already produces, but its tests run
  against any verdict, so it is independently testable
- **US3 (Phase 5)**: Depends on Foundational. T084 and T092 additionally need the directory walk from
  T061 (US1)
- **US4 (Phase 6)**: Depends on Foundational, which provides the built-in rule set to override
- **Polish (Phase 7)**: Depends on the stories being delivered

### Critical path

```text
T001 → T004 → T011 → T012 → T017 → T020 → T023 → T024 → T026 → T028 → T031 → T032
                                                                            ↓
                                              US1 → US2 → US3 → US4 → Polish
```

T032 (`Engine::scan`) is the single chokepoint: everything upstream is types, rule loading, and
scoring; everything downstream is detection and presentation. It is the one task where a wrong call is
expensive to unwind, so review the pipeline shape before writing it.

### Within Each User Story

- Fixtures before the tests that consume them
- Tests before implementation, confirmed failing first
- Decoders before the pipeline that composes them (T051, T053, T054 → T055)
- Structural pre-pass before suppression (T048 → T049)
- Score properties before the formula (T030 → T031)
- Core detection before CLI rendering
- Story complete and checkpointed before starting the next priority

### Parallel Opportunities

- Setup: T002, T003, T006, T007, T008, T009 parallel
- Foundational: T011, T013, T018, T020, T027, T030, T033, T034, T035, T036 parallel. The `verdict.rs`
  tasks (T012, T017) and the `ruleset/` chain (T020→T023→T024) serialise on shared files
- US1: six fixture tasks (T037–T042) parallel; five detector tasks (T050–T054) parallel, each owning
  its own file. T043 is sequential only because 200 fixtures is a sustained effort, not a conflict
- US2: all four test tasks (T065–T068) parallel
- US3: T076, T077, T081, T082, T083, T084, T085, T086, T087 parallel
- Across stories: once Foundational completes, US1–US4 can be staffed concurrently

---

## Parallel Example: User Story 1

```bash
# All positive-fixture authoring together — different directories, no shared files:
Task: "Create positive fixtures for instruction override in tests/fixtures/override/"
Task: "Create positive fixtures for concealment in tests/fixtures/concealment/"
Task: "Create positive fixtures for confusables in tests/fixtures/confusable/"
Task: "Create positive fixtures for encoding in tests/fixtures/encoding/"
Task: "Create positive fixtures for boundary forgery in tests/fixtures/boundary/"
Task: "Create positive fixtures for solicitation in tests/fixtures/solicitation/"

# All detectors together — each owns its own file:
Task: "Implement the concealment scanner in crates/core/src/detect/concealment.rs"
Task: "Implement Tags-block and variation-selector decoding in crates/core/src/decode/unicode.rs"
Task: "Implement per-token confusable analysis in crates/core/src/detect/confusable.rs"
Task: "Implement the base-64 decoder in crates/core/src/decode/base64.rs"
Task: "Implement hex, rot13, reversal, and leetspeak decoders in crates/core/src/decode/"
```

---

## Implementation Strategy

### MVP First (User Story 1 only)

1. Phase 1: Setup
2. Phase 2: Foundational — blocks everything, so do not shortcut it
3. Phase 3: User Story 1
4. **STOP and VALIDATE**: run quickstart Scenarios 1 and 2. Check both directions — payloads are
   detected, *and* `tests/fixtures/benign/threat_model_excerpt.md` reports clean. A tool that flags
   security documentation will not be adopted by the people who read security documentation
5. Demo: `plz scan` against a real skill file

### Incremental Delivery

1. Setup + Foundational → foundation ready
2. US1 → human-usable scanner (MVP)
3. US2 → hooks can gate on it; this is where it becomes a firewall rather than a linter
4. US3 → safe to put in the hot path of every tool call
5. US4 → survives contact with a real codebase

US3 before US4 is deliberate: until bounds are enforced, content cannot steer analysis, and the fuzz
campaign is running, the tool should not sit in a path an attacker can reach — and US2's whole purpose
is putting it exactly there.

### Parallel Team Strategy

After Foundational: one developer per story. US1 is the largest and can itself be split — detectors are
file-independent, so concealment, confusables, and the decoders parallelise cleanly. T043's 200
hard-negative fixtures is the single largest sustained effort in the list and is worth starting early,
because SC-003 cannot be evaluated at all until it exists.

---

## Traceability

Every requirement to the tasks that discharge it. This exists so T116's verification is a lookup rather
than a re-derivation, and so a requirement cannot lose its coverage silently during a refactor of this
list. Security-relevant requirements additionally carry their identifier inline in the task description.

| Requirement | Tasks |
|---|---|
| FR-001 verdict shape | T012, T017 |
| FR-001a score aggregation | T030, T031 |
| FR-001b aggregate before truncation | T030, T031, T090 |
| FR-002 reason contents | T012, T046 |
| FR-003 three outcomes with cause | T012, T014, T017 |
| FR-004 never clean when incomplete | T014, T015, T017, T079, T080 |
| FR-005 rule set and engine identity | T012, T024, T100 |
| FR-006 caller decides | T032, T071 |
| FR-007 bounded reasons, declared | T029, T078, T090 |
| FR-008 override detection | T037, T044, T057 |
| FR-009 concealment detection | T038, T044, T050, T051 |
| FR-010 confusables, non-English safe | T039, T043, T044, T052 |
| FR-011 five encoding families | T040, T044, T047, T053, T054, T055 |
| FR-012 boundary forgery | T041, T044, T057 |
| FR-013 solicitation | T042, T044, T058 |
| FR-014 instruction versus description | T043, T045, T048, T049 |
| FR-015 classes independently addressable | T011, T105 |
| FR-016 linear time | T029, T087 |
| FR-017 max input size | T078, T079, T088 |
| FR-018 max decode depth | T078, T089 |
| FR-019 terminates on every input | T076, T085, T086, T091 |
| FR-020 content cannot steer analysis | T081, T082 |
| FR-021 excerpts neutralised | T018, T019 |
| FR-022 rules are data | T020, T022 |
| FR-023 runtime rule loading | T098, T099, T102, T103 |
| FR-024 reject malformed rule sets | T021, T023, **T108 (spec gap)** |
| FR-025 default set needs no config | T025, T026 |
| FR-026 file, directory, stdin | T061 |
| FR-027 human and machine output | T062, T066, T070, T072 |
| FR-028 six status codes | T067, T071 |
| FR-029 configurable threshold | T060 |
| FR-030 reproducible | T068, T070 |
| FR-031 no network | T034, T035 |
| FR-032 per-target verdicts and summary | T073 |
| FR-032a unreadable target inconclusive | T084, T092 |
| FR-032b summary precedence | T016, T073, T084 |
| SC-001 output completeness | T046 |
| SC-001a recorded walkthrough | T114 |
| SC-002 per-class fixture detection | T044 |
| SC-003 ≤1% over ≥200 negatives | T043, T045 |
| SC-004 warm and cold latency | T093, T094 |
| SC-005 linear growth exponent | T087 |
| SC-006 1M cumulative fuzz | T085, T086, T095, T096 |
| SC-007 incomplete never clean | T015, T079 |
| SC-008 findings name rule and span | T046 |
| SC-009 hook integrates from docs alone | T074, T075 |
| SC-010 tune without rebuild | T098, T099 |
| SC-011 byte-identical output | T068, T070 |
| SC-012 verdict attributable to rules | T100 |

Constitution gates not tied to a numbered requirement: `wasm32` build (T036), dependency gating (T034),
concurrent-scan safety (T083), attribution (T008, T112), declared gaps (T009, T111).

## Notes

- **116 tasks.** Test tasks are mandatory here, not optional: the constitution requires detection
  behaviour to be expressed as failing tests first, and requires property and fuzz coverage of the bounds
- **T043 is load-bearing and easy to under-deliver.** 200 hard negatives including genuine technical
  security prose is what makes SC-003 meaningful. T045 fails the run if the set is short, so the
  criterion cannot be quietly satisfied with twenty files
- **T108 amends the spec, not the code.** It closes the last gap `/speckit-analyze` found that the
  clarification session did not reach, and without it the implementation stays stricter than the
  requirement it claims to satisfy
- Reporting the Unicode Tags gap in bee's `src/safe_text.rs` (research D6) has been **removed from this
  list** — it is real and worth doing, but it changes another repository and is not this feature's
  deliverable. It belongs in a project-level TODO
- [P] tasks touch different files. Where two tasks share a file they are sequenced, which is why the
  `verdict.rs` and `ruleset/` tasks are not marked parallel despite being conceptually independent
- Commit after each task or logical group. Per the constitution's attribution gate, any commit
  containing agent-authored work carries the co-author trailer
- Confirm each test fails before implementing it. A test that passes on first write is testing something
  other than what it claims
