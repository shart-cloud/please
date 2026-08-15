# Implementation Plan: Trustworthy Core — Rule Preparation & Verdict Finalization

**Branch**: `002-trustworthy-core` | **Date**: 2026-08-15 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/002-trustworthy-core/spec.md`

## Summary

Concentrate two transitions behind deep seams, and in doing so close two defects that the current structure
makes unenforceable.

**Preparation** owns everything between a rule source and an executable scanner: parsing, resolution, identity,
resource validation, provenance, and the compiled matching state. Its guarantee is that no scanning capability
exists for caller-supplied rules that have not been proven to compile within budget — enforced by there being
no construction path that omits validation, rather than by asking callers to validate first. Feature 001 asked;
nothing did.

**Finalization** owns everything between detector observations and a verdict: scoring, ordering, truncation,
precedence, banding, and reason construction. Its guarantee is that only it can produce a verdict and detectors
can only produce observations — both compile errors, not conventions.

Two behaviour changes fall out. Caller rule sets containing a resource bomb start being rejected instead of
degrading during scanning. And `DetectionClass::Encoding` is removed, because it named a delivery mechanism
while the design says an encoding is never itself a finding — the contradiction that made a base-64 override
undetectable under either `--classes override` or `--classes encoding` alone.

Accuracy is explicitly held constant. The security-prose false positives stay open, and the fixture numbers are
recorded before and after so the accuracy work that follows starts from a known baseline.

## Technical Context

**Language/Version**: Rust, stable. Unchanged from 001.

**Primary Dependencies**: Unchanged. No dependency is added or removed by this feature — the allow-list should
be byte-identical at 27 crates when it lands, which is itself a check worth running.

**Storage**: None.

**Testing**: `cargo test`, `proptest` for the invariant properties (moving to finalization's interface),
`criterion` for the cold-start and delta-validation figures, plus a **compile-fail** test, which is new: "a
detector cannot construct a reason" is a claim about the type system and can only be verified by something that
fails to build.

**Target Platform**: Unchanged. `wasm32-unknown-unknown` must still build the core.

**Project Type**: Rust workspace — embeddable library plus thin CLI.

**Performance Goals**: Cold start must not regress (SC-104). Delta validation must be measurably cheaper than
whole-set validation (SC-105). No pattern compiled twice (SC-106).

**Constraints**: Accuracy unchanged in either direction (SC-113). No test silently lost (SC-112). All 001
guarantees preserved in meaning. Two behaviour changes isolated to their own commits.

**Scale/Scope**: Roughly 10 built-in rules today, caller sets expected to be small. Delta validation matters
because the built-in set will grow while caller additions stay few.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Gates from `.specify/memory/constitution.md` v1.0.0. The interesting column is the first: this feature exists
because several gates that 001's plan recorded as PASS were passing on paper.

| Gate | Principle | Pre-Phase 0 | Post-Phase 1 | How it is discharged |
|---|---|---|---|---|
| Verdict reports; caller enforces | I | PASS | PASS | Unchanged. Finalization still reports; policy still disposes |
| Incomplete analysis is never clean | I | PASS | PASS | Same invariant, now with one enforcement site and no way around it |
| Optional tier degrades to inconclusive, never clean | I | PASS | PASS | Gap vocabulary covers it explicitly |
| Linear-time analysis | II | PASS | PASS | Untouched. Match caps and bounds stay in the matcher |
| Bounded input and recursion | II | PASS | PASS | Bounds move into the plan; enforcement is unchanged |
| **Rule sets are validated against resource limits** | II | **VIOLATED** | PASS | 001 specified whole-set rejection; the check has zero call sites. FR-102/103 make it unreachable-to-skip |
| No backtracking patterns | II | PASS | PASS | Structural, from the matching engine's syntax |
| Fuzzed analysis path | II | PASS | PASS | Targets unchanged; entry point relocates |
| Rules are reviewable data | III | PASS | PASS | Rule format unchanged |
| Rule set identified in every verdict | III | PASS | PASS | Strengthened: identity now covers provenance and validation state (FR-111) |
| **Detection classes independently addressable** | III, V | **VIOLATED** | PASS | FR-131/133 — one class per observation, one filter application |
| Per-source stratified metrics | IV | **DEFERRED** | **DEFERRED** | Still the evaluation harness's job. Unchanged by this feature |
| False-positive gate in CI | IV | **FAILING** | **FAILING** | Deliberately unchanged — SC-113 requires accuracy to stay put. See Complexity Tracking |
| Gaps stated explicitly | IV | PASS | PASS | `docs/limits.md` unchanged; this feature adds no accuracy claim |
| No corpus text vendored | IV | PASS | PASS | Unchanged |
| Runtime-free, offline, no model | V | PASS | PASS | No dependency change; core still has no clock, filesystem, or network |
| `wasm32` build proven in CI | V | PASS | PASS | Unchanged |
| Optional deps gated by test | V | PASS | PASS | Allow-list should be byte-identical; asserted as part of done |
| CLI holds no logic the library lacks | V | PASS | PASS | Strengthened: the CLI loses the ability to construct a verdict at all |

**Pre-Phase 0 verdict**: two outright violations of principles 001's plan recorded as satisfied. Both are
reproducible from a shell, and both trace to the same root cause — a guarantee stated in a specification and
implemented as an operation a caller may omit.

**Post-Phase 1 verdict**: all gates pass except the two knowingly carried: per-source metrics (deferred to the
evaluation harness) and the false-positive gate (failing, and required by SC-113 to keep failing identically).

The lesson worth writing down: 001's Constitution Check was not dishonest, it was *unverified*. A gate whose
evidence is "the design provides for this" passes review and fails in production. The gates in this table are
phrased so that each names a mechanism, and Phase 2 must produce a passing check for each.

## Project Structure

### Documentation (this feature)

```text
specs/002-trustworthy-core/
├── plan.md                      # This file
├── spec.md                      # 5 stories, 32 FR, 13 SC
├── research.md                  # Phase 0 — P1..P7
├── data-model.md                # Phase 1 — entities, flow, preserved invariants
├── quickstart.md                # Phase 1 — 10 scenarios, 10 of 13 checks failing today
├── contracts/
│   ├── preparation.md           # rules → executable state
│   └── finalization.md          # evidence → verdict
├── checklists/
│   └── requirements.md
└── tasks.md                     # Phase 2 (/speckit-tasks — not created here)
```

### Source Code (repository root)

Two new module trees; four existing modules shrink. Nothing outside `crates/core/src` moves.

```text
crates/core/src/
├── lib.rs                       # re-exports verdict types from their new home
├── prepare/                     # NEW — owns rules → executable state
│   ├── mod.rs                   #   the three entry points, all validating
│   ├── provenance.rs            #   opaque type, private discriminant (P1)
│   ├── validate.rs              #   cheap tier + expensive tier, retention
│   └── prepared.rs              #   PreparedRuleset, ValidationRecord
├── matcher/                     # NEW — owns the rule position space privately (P4)
│   ├── mod.rs                   #   observations out, no index escapes
│   ├── prefilter.rs             #   was crates/core/src/prefilter.rs
│   └── patterns.rs              #   was detect/pattern.rs; slots pre-fillable
├── finalize/                    # NEW — owns evidence → verdict
│   ├── mod.rs                   #   the only verdict producer
│   ├── types.rs                 #   Verdict, Reason, Incompleteness — pub(super) ctors (P3)
│   ├── evidence.rs              #   write-only handle for detectors (P6)
│   ├── plan.rs                  #   ScanPlan; class filter resolved once
│   └── score.rs                 #   was score.rs
├── engine.rs                    # SHRINKS — orchestration only
├── detect/
│   ├── mod.rs                   # SHRINKS — dispatch; loses Hit→Reason
│   ├── concealment.rs           # unchanged
│   └── confusable.rs            # unchanged
├── decode/                      # loses the gap-policy booleans (P6)
├── structure.rs                 # unchanged
├── sanitize.rs                  # unchanged
├── policy.rs                    # unchanged
├── ruleset/                     # parsing and rule types; validation moves to prepare/
└── verdict.rs                   # DELETED — types live in finalize/types.rs

crates/core/tests/
├── preparation.rs               # NEW — construction paths, delta cost, retention
├── finalization.rs              # NEW — absorbs invariants.rs; evidence in, verdict out
├── classes.rs                   # NEW — 10 class × delivery combinations
├── seams.rs                     # NEW — no positional identifier exchanged
├── compile_fail/                # NEW — detector cannot construct a reason
├── invariants.rs                # DELETED — moves to finalization.rs
├── scan.rs                      # SHRINKS — keeps pipeline claims, sheds verdict-shape claims
├── fixtures.rs                  # unchanged — the SC-113 baseline
└── …                            # sanitize, ruleset_load, score, support unchanged
```

**Structure Decision**: three new module trees rather than one, because they own three different questions and
have three different failure modes. `prepare` is the only route from rules to an executable scanner; `matcher`
exists to make the rule position space unobservable; `finalize` is the only route from evidence to a verdict.

`verdict.rs` is deleted rather than kept as a re-export shim. Research P3 established that a sibling module
cannot be granted privileged construction rights — `pub(in crate::finalize)` does not compile for an item
outside that tree — so the types must live inside finalization for the guarantee to exist at all. The public
naming path is preserved by re-export from `lib.rs`, so embedders are unaffected.

`matcher` merges the current `prefilter.rs` and `detect/pattern.rs`. They are separate today for no reason
beyond having been written separately, and their separation is exactly what forces a positional identifier
across a seam.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| The constitution's false-positive gate stays **failing** through this feature | SC-113 requires accuracy to be unchanged in either direction, so the gate must fail identically before and after. Fixing it here would confound a structural change with an accuracy change and destroy the baseline the next iteration needs | Fixing accuracy as part of this work was rejected: the two changes have different risk profiles and different reviewers would want to see them separately. A refactor that also improves detection is a refactor nobody can safely revert |
| Principle IV's per-source stratified metrics remain deferred | Still requires the evaluation harness, still out of scope, unchanged by this feature | Nothing here brings it closer or further. Recorded so the deferral is not silently inherited — this is the **fifth** consecutive checkpoint at which it has been accepted, and it remains true that no accuracy claim about this tool may be published until the harness exists |
| `verdict.rs` is deleted rather than deprecated | The guarantee requires the types to live inside finalization (research P3); a shim would leave a second construction path, which is the thing being removed | Keeping `verdict.rs` as a re-export shim was rejected: it reads as harmless and would let a future edit add a constructor there, restoring the leak invisibly |
| Three new module trees rather than one "core internals" module | Three distinct questions with three distinct failure modes. Merging them would produce one module whose interface is as complex as its implementation — the definition of shallow | One module was rejected on the deletion test: deleting a combined module would scatter complexity across the same four files it came from, which is no improvement |
| A compile-fail test, a category the project did not previously have | FR-121 and SC-108 assert what code *cannot* be written. That is unverifiable by any test that compiles | Asserting it in prose was rejected — 001 asserted several guarantees in prose and this feature exists because of it |
