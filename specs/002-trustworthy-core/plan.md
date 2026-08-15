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

| Gate | Principle | Pre-Phase 0 | Final | Discharged by — mechanism, and the commit |
|---|---|---|---|---|
| Verdict reports; caller enforces | I | PASS | PASS | `tests/seams.rs::exactly_one_place_constructs_a_verdict`; the CLI branches on `outcome()` and the core exposes no enforcement. `5d2272a` |
| Incomplete analysis is never clean | I | PASS | PASS | `tests/finalization.rs::clean_implies_nothing_found_and_nothing_missed` (proptest) plus four case tests, now against **one** enforcement site. `5d2272a` |
| Optional tier degrades to inconclusive, never clean | I | PASS | PASS | `tests/finalization.rs::not_clean_when_an_optional_tier_was_unavailable`. `5d2272a` |
| Linear-time analysis | II | PASS | PASS | Match cap unchanged, now inside the matcher: `matcher::patterns::tests::collection_stops_at_the_cap_and_says_so`. `d1607f0` |
| Bounded input and recursion | II | PASS | PASS | `finalize::plan::tests::a_plan_carries_the_policys_bounds_verbatim`; `decode::tests::depth_is_bounded_and_the_bound_is_reported`. `5d2272a`, `a3ab27e` |
| **Rule sets are validated against resource limits** | II | **VIOLATED** | **PASS** | `tests/preparation.rs::every_public_construction_path_rejects_a_resource_bomb` — an enumeration of all seven routes against `tests/fixtures/rules/bomb.toml`, plus the positive control. `4333204` |
| No backtracking patterns | II | PASS | PASS | Structural, from the engine's syntax: `prepare::validate::tests` and `ruleset::validate::tests::lookaround_is_not_expressible_and_the_cheap_tier_catches_it`. `4333204` |
| Fuzzed analysis path | II | PASS | **CARRIED** | Unchanged by this feature and **still not built** — 001's T095/T096 own it. Recorded as carried rather than PASS, because nothing here establishes it |
| Rules are reviewable data | III | PASS | PASS | `rules/builtin.toml` is still TOML with a comment per rule; `tests/ruleset_load.rs` (35 tests) |
| Rule set identified in every verdict | III | PASS | PASS | Strengthened: `tests/preparation.rs::two_rule_sets_differing_only_in_trust_origin_are_distinguishable` and `::identity_is_stable_across_preparations`. `4333204` |
| **Detection classes independently addressable** | III, V | **VIOLATED** | **PASS, 8 of 10** | `tests/classes.rs` (8 tests) and `cli.rs::the_removed_encoding_class_is_rejected_rather_than_silently_accepted`. The two structural×encoded combinations are **not** addressable and are the suite's only `#[ignore]`d test. `aaac4ab` |
| Per-source stratified metrics | IV | **DEFERRED** | **DEFERRED** | Still `please-eval`'s job, still unbuilt. Unchanged by this feature |
| False-positive gate in CI | IV | **FAILING** | **FAILING** | Still failing, at **1** false positive rather than 8. The gate fails on any false positive while the corpus is under 200 cases, so the count moving does not change its colour. `fb172fe` |
| Gaps stated explicitly | IV | PASS | PASS | `docs/limits.md` gained four sections and two amendments — the pre-Phase-1 claim that it would be "unchanged" was wrong, and stating the gaps is the gate. `fb172fe`, `d1607f0` |
| No corpus text vendored | IV | PASS | PASS | `tests/fixtures/rules/bomb.toml` is authored, not vendored; no fixture text was added from any corpus |
| Runtime-free, offline, no model | V | PASS | PASS | `ci/check-core-isolation.sh` — no network, filesystem, subprocess, or clock in `crates/core/src`. Run at every phase |
| `wasm32` build proven in CI | V | PASS | PASS | `cargo build -p please-core --target wasm32-unknown-unknown`, run at every phase and in `ci.yml` |
| Optional deps gated by test | V | PASS | PASS | `ci/check-dependencies.sh` — exact 27-crate match, verified unchanged at T082. Dev graph moved by `trybuild` alone |
| CLI holds no logic the library lacks | V | PASS | PASS | Strengthened structurally: `tests/compile_fail/only_finalization_produces_a_verdict.rs` — the CLI *cannot* construct a verdict. `5d2272a`, `d8eae0d` |
| **Built-in rule set's validity established** | II | *not a gate in 001* | **PASS** | Added because 001 had no such gate and its absence is why the fast path was unsound. `ci.yml` job `builtin-validation`, running `tests/preparation.rs::the_builtin_rule_set_passes_compiled_validation_at_default_limits`. `4333204` |

### T086: what this re-check changed

Three rows were wrong as written at Post-Phase 1, and the point of requiring a mechanism per gate is that
running the mechanism is what found them:

* **Fuzzed analysis path** was recorded PASS. Nothing in this feature or 001 establishes it — the fuzz targets
  are 001's T095/T096 and are unbuilt. It is now CARRIED, which is the honest colour for a gate whose evidence
  does not exist.
* **Gaps stated explicitly** was justified with "`docs/limits.md` unchanged; this feature adds no accuracy
  claim". It gained four sections. The justification was written on the assumption that 002 would be purely
  structural, and detection work landing changed that.
* **False-positive gate** was justified as "deliberately unchanged — SC-113 requires accuracy to stay put".
  Accuracy did move, at the examiner's direction, and the authorised deviation is recorded in
  `docs/002-accuracy-baseline.txt`. The gate's *colour* is unchanged; the reason given for it was not.

One row was added. 001 had no gate for the built-in rule set's own validity, and that absence is precisely why
its fast path rested on nothing. A missing gate is invisible to a gate review, which is the failure mode one
level up from an unverified gate.

**Pre-Phase 0 verdict**: two outright violations of principles 001's plan recorded as satisfied. Both are
reproducible from a shell, and both trace to the same root cause — a guarantee stated in a specification and
implemented as an operation a caller may omit.

**Final verdict (T086)**: both violations are closed by a named, passing check. Three gates remain
non-passing and each is carried deliberately: per-source metrics (deferred to the evaluation harness), the
false-positive gate (failing at 1 rather than 8, and the gate fails on any false positive below the 200-case
minimum), and the fuzz path (unbuilt, and previously mis-recorded as PASS). Independent addressability passes
at 8 of 10 combinations, with the shortfall named rather than rounded up.

The lesson worth writing down: 001's Constitution Check was not dishonest, it was *unverified*. A gate whose
evidence is "the design provides for this" passes review and fails in production.

That lesson recurred inside this feature. Three of the rows above were wrong when written at Post-Phase 1 —
not carelessly, but because they were predictions about work not yet done, and two of the three were falsified
by the work itself. The mechanism column is what caught them: a gate that has to name a command cannot be
justified by an expectation. `docs/002-validation.md` records the T082–T085 runs.

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
