# Implementation Plan: Structural Detection & Scan CLI

**Branch**: `001-structural-detection-cli` | **Date**: 2026-08-15 | **Spec**: [spec.md](./spec.md)

**Input**: Feature specification from `/specs/001-structural-detection-cli/spec.md`

## Summary

Deliver the first shippable slice of PLEASE: a Rust engine that judges whether a piece of text is
trying to instruct the agent reading it, and a `plz` binary that exposes that judgement to humans and
to hooks. The engine returns one of three outcomes — clean, risk found, or inconclusive — and never
reports clean for analysis that did not complete.

Detection is structural rather than semantic: six independently addressable classes (instruction
override, concealment, confusables, encoding, boundary forgery, solicitation), driven by declarative
TOML rules. Two design decisions carry most of the weight. Matching is two-stage — a single literal
automaton gates lazy per-rule pattern compilation — because the cost a hook actually pays is
cold-start, not steady-state throughput. And encoded content is reported only when what it *decodes
to* trips a rule, which removes the false-positive class that would otherwise make the tool
unusable on ordinary files.

`please-core` carries no runtime, no clock, no filesystem, and no network, and CI proves it builds
for `wasm32-unknown-unknown`. `please-cli` is a thin wrapper holding no detection logic.
`please-eval` exists but sits outside the workspace so its heavy dependencies cannot reach the
shipping crates.

## Technical Context

**Language/Version**: Rust, stable. 1.96.0 verified on the development host; MSRV to be pinned at
first release from the actual floor of the dependency set.

**Primary Dependencies**: `regex` and `aho-corasick` (finite-automata matching, linear-time by
construction); `unicode-security` and `unicode-normalization` (UTS #39 confusables, mixed-script,
normalisation); `base64`; `toml` (rule sets); `serde` and `serde_json` (optional in core, enabled by
the CLI); `clap` (CLI only). Dev/test: `proptest`, `criterion`, `insta`, `cargo-fuzz`.

**Storage**: None. Rules are read from files by the caller; the built-in set is embedded in the
binary. Nothing is persisted between runs.

**Testing**: `cargo test`, `proptest` for bounds properties, `cargo-fuzz` (libFuzzer) for robustness,
`criterion` for the linearity and throughput gates, `insta` for CLI output snapshots.

**Target Platform**: Linux, macOS, and Windows for the CLI; `wasm32-unknown-unknown` for the core,
proven in CI. No platform-specific code in the core.

**Project Type**: Rust workspace — an embeddable library plus a thin CLI over it.

**Performance Goals**: Warm per-scan p95 ≤ 10 ms at 4 KB input; sustained throughput ≥ 10 MB/s on one
core (SC-004). Cold start (process launch to first verdict) ≤ 25 ms, budgeted and measured separately
per research D4.

**Constraints**: Analysis linear in input length with no superlinear input (FR-016, SC-005). Bounded
input size, decode depth, matches per rule, and reasons per verdict. No async runtime, no network, no
required model, no clock in the core. Byte-identical machine-readable output across runs and hosts
(SC-011). `#![forbid(unsafe_code)]` in the core.

**Scale/Scope**: Roughly 40–80 built-in rules across six classes at first release. Inputs up to 1 MiB
by default — an order of magnitude above the 82,300-byte corpus maximum. One engine instance serves
concurrent scans.

## Constitution Check

*GATE: Must pass before Phase 0 research. Re-check after Phase 1 design.*

Gates derived from `.specify/memory/constitution.md` v1.0.0.

| Gate | Principle | Pre-Phase 0 | Post-Phase 1 | How it is discharged |
|---|---|---|---|---|
| Verdict reports; caller enforces | I | PASS | PASS | `scan` returns `Verdict`, never a decision. `--threshold` and hook policy are caller-side (contracts/cli.md, core-api.md) |
| Incomplete analysis is never clean | I | PASS | PASS | `Outcome::Inconclusive` + `incomplete`; `clean` requires both accumulators empty; asserted as a proptest invariant (data-model.md, D11) |
| Linear-time analysis | II | **RISK** | PASS | Match iteration is `O(m·n²)`; resolved by bounded match collection making it `O(K·m·n)` (D2). Gated by a criterion exponent test |
| Bounded input and recursion | II | PASS | PASS | `max_input_bytes`, `max_decode_depth`, cycle guard; each bound reported as an `Incompleteness` |
| No backtracking patterns | II | PASS | PASS | Enforced by construction: the engine cannot express look-around or backreferences, so a catastrophic rule fails to load (D1, contracts/ruleset.md) |
| Fuzzed analysis path | II | PASS | PASS | `cargo-fuzz` targets on the scan entry point and each decoder (D11) |
| Rules are reviewable data | III | PASS | PASS | TOML rule sets, runtime-loadable, `description` required (contracts/ruleset.md) |
| Rule set identified in every verdict | III | PASS | PASS | `ruleset{name,version,digest}` over the resolved set (contracts/verdict.schema.json) |
| Per-source stratified metrics | IV | **DEFERRED** | **DEFERRED** | Requires the evaluation harness; out of scope by spec. Fixture-based SC-002/SC-003 apply here. See Complexity Tracking |
| False-positive gate in CI | IV | **ILL-DEFINED** | PASS | Rate now has a denominator: ≤1% over ≥200 hard negatives incl. technical security prose, at the default threshold (SC-003). Fixture-era band values recorded alongside the metric |
| Every security-relevant behaviour is testable | Workflow | **VIOLATED** | PASS | FR-020 restated testably — rule-like content must score as inert prose, and verdicts must be independent of scan order |
| No-network claim mechanically verified | V | **PROXY ONLY** | PASS | Static gate on the engine's own sources plus the dependency allow-list. The allow-list alone cannot prove it, since `std::net` needs no dependency (D15) |
| Score aggregation defined | I, IV | **UNDEFINED** | PASS | Maximum severity plus capped distinct-class bonus, length- and count-insensitive, aggregated before truncation (D13, FR-001a/b) |
| Inconclusive cause is machine-readable | I | **UNREPRESENTABLE** | PASS | `incomplete[].cause` covers bounds and failures alike, including `target_unreadable` (D14, FR-032a) |
| Gaps stated explicitly | IV | PASS | PASS | Multilingual gap, heuristic quoting limit, provisional band calibration — all stated in spec Assumptions and tool docs (D7, D8) |
| No corpus text vendored | IV | PASS | PASS | Fixtures authored or permissively licensed; corpus reached only by the deferred eval crate |
| Runtime-free, offline, no model | V | PASS | PASS | Core has no async, no network, no clock (D10), embedded default rule set |
| `wasm32` build proven in CI | V | PASS | PASS | `cargo build -p please-core --target wasm32-unknown-unknown` |
| Optional deps gated by test | V | PASS | PASS | Dep-guard test against a committed allow-list; `please-eval` excluded from the workspace (D12) |
| CLI holds no logic the library lacks | V | PASS | PASS | CLI does argument parsing, target reading, and formatting only |

**Pre-Phase 0 verdict** *(first pass, before the clarification session)*: proceeded with one identified
risk — the linear-time gate could not be asserted without knowing the matching engine's iteration
complexity, which is what Phase 0 was for.

**Second pass**: `/speckit-analyze` found five gates that the first plan had marked PASS or omitted
entirely, shown above in their pre-clarification state. Two were constitution violations: a
security-relevant MUST with no test (FR-020) and a mandated CI gate with no denominator (SC-003). The
column is left in rather than quietly overwritten, because the useful record is not that the gates pass
now — it is which ones did not, and were caught by review rather than in production.

**Post-Phase 1 verdict**: all gates pass except the per-source metrics gate, which the specification
defers to the evaluation harness feature. That deferral is recorded below rather than waved through —
it is the one place where this feature can pass every criterion it sets itself while its real-world
accuracy remains unmeasured. It has now been accepted at four consecutive checkpoints, which is
precisely how a real gap becomes invisible, so it is restated here in the plainest terms available: **no
accuracy claim about this tool may be published until the evaluation harness exists.**

## Project Structure

### Documentation (this feature)

```text
specs/001-structural-detection-cli/
├── plan.md                      # This file
├── spec.md                      # Feature specification
├── research.md                  # Phase 0 — D1..D12, plus D13..D16 from clarification
├── data-model.md                # Phase 1 — entities and invariants
├── quickstart.md                # Phase 1 — runnable validation
├── contracts/
│   ├── verdict.schema.json      # Machine-readable verdict (caller-facing)
│   ├── cli.md                   # `plz` surface, status codes, stream discipline
│   ├── ruleset.md               # TOML rule format and load-time validation
│   └── core-api.md              # Rust embedding surface
├── checklists/
│   └── requirements.md          # Spec quality checklist
└── tasks.md                     # Phase 2 (/speckit-tasks) — regenerate after this pass
```

### Source Code (repository root)

```text
Cargo.toml                       # workspace: crates/core, crates/cli; excludes crates/eval
rust-toolchain.toml              # stable
rustfmt.toml
rules/
└── builtin.toml                 # the default rule set, embedded at build time

crates/core/                     # please-core — #![forbid(unsafe_code)], wasm32-clean
├── src/
│   ├── lib.rs                   # Engine, scan entry point
│   ├── verdict.rs               # Outcome, Verdict, Reason, Incompleteness, Span, RiskLevel,
│   │                            # EngineId, QuotingContext, TargetRef
│   ├── policy.rs                # ScanPolicy and its bounds
│   ├── ruleset/
│   │   ├── mod.rs               # Ruleset, resolution, digest
│   │   ├── parse.rs             # TOML → Rule
│   │   └── validate.rs          # load-time limits (D3)
│   ├── prefilter.rs             # aho-corasick literal gate (D4)
│   ├── structure.rs             # quoting-region pre-pass (D8)
│   ├── decode/
│   │   ├── mod.rs               # bounded, cycle-guarded pipeline (D5)
│   │   ├── base64.rs  hex.rs  rot13.rs  reversed.rs  leetspeak.rs
│   │   └── unicode.rs           # tag block, variation selectors (D6)
│   ├── detect/
│   │   ├── mod.rs               # class dispatch
│   │   ├── pattern.rs           # lazy-compiled pattern rules
│   │   ├── concealment.rs       # invisible/bidi/tag scanning
│   │   └── confusable.rs        # UTS #39, per token (D7)
│   ├── score.rs                 # max + capped distinct-class bonus, banding (D13)
│   └── sanitize.rs              # excerpt neutralisation (FR-021)
├── benches/scaling.rs           # SC-005 exponent gate, SC-004 throughput
├── fuzz/fuzz_targets/           # scan.rs, decode.rs
└── tests/                       # bounds.rs (proptest), invariants.rs, fixtures.rs

crates/cli/                      # please-cli — binary `plz`
├── src/
│   ├── main.rs
│   ├── args.rs                  # clap surface (contracts/cli.md)
│   ├── target.rs                # path/dir/stdin reading, lexicographic walk
│   ├── render/human.rs  render/json.rs
│   └── exit.rs                  # status-code mapping
└── tests/cli.rs                 # insta snapshots, status-code coverage

crates/eval/                     # please-eval — EXCLUDED from the workspace (own lockfile)
└── (corpus adapters, manifest, stratified metrics — separate feature)

tests/
├── dep_guard.rs                 # Principle V allow-list
└── fixtures/                    # see quickstart.md for layout

.github/workflows/ci.yml         # test, clippy, wasm32 build, bench gate, fuzz smoke, dep guard
docs/
├── research/corpus-analysis.md  # measured corpus facts
├── attribution.md               # agent- vs human-authored components
└── limits.md                    # declared gaps, stated in the product not just the spec
```

**Structure Decision**: A two-crate workspace with a third crate excluded from it. `crates/core`
holds every detection decision so that the library and the CLI cannot diverge, as Principle V
requires; `crates/cli` is confined to argument parsing, target reading, rendering, and status-code
mapping. `crates/eval` is created now but placed in `workspace.exclude` with its own lockfile,
because its corpus tooling needs data-frame and network dependencies that must never appear in a
`cargo build --workspace` resolution — the dependency guard would otherwise be defeated by a
transitive edge from a development tool. This mirrors the arrangement bee uses for its `xtask` crate,
so a contributor moving between the two repositories meets a familiar shape.

Rules live in `rules/builtin.toml` at the repository root rather than inside the core crate's
sources, because they are a reviewable product artifact rather than code — a reader looking for what
the scanner detects should find it without descending into `src/`.

## Complexity Tracking

| Violation | Why Needed | Simpler Alternative Rejected Because |
|-----------|------------|-------------------------------------|
| Principle IV's per-source stratified metrics and corpus false-positive gate are **not** satisfied by this feature | The corpus adapter, sampling manifest, and metrics pipeline are a separate feature by the spec's own scoping; corpus text also cannot be vendored, so measurement needs machinery this slice does not build | Building the evaluation harness inside this feature was rejected as making the first slice unreviewable. The consequence is stated plainly: this feature can pass all twelve of its success criteria while its accuracy against real attack data remains unmeasured. Fixture-based SC-002 and SC-003 bound the risk but do not remove it, and no accuracy claim may be published until the harness lands |
| `please-core` takes seven dependencies rather than none | The feature brief asked for a dependency-free core, which is stricter than Principle V, whose testable claims are no async runtime, no network, no required model, and a working `wasm32` build — all satisfied | Hand-writing a linear-time multi-pattern matcher and a UTS #39 confusables table was rejected: it puts novel, unproven code in precisely the component whose correctness is the product. The `regex` dependency additionally *enforces* Principle II, since its syntax cannot express a backtracking pattern |
| Caller-supplied rule sets are validated against resource limits, which FR-024 does not currently require | FR-023 lets a caller supply rules, so a rule set is untrusted input. A twenty-character pattern can expand to an enormous automaton (D3), making a copied third-party rule set a memory-exhaustion path into the tool | Trusting rule authors was rejected as inconsistent with the project's own threat model. **Still an open specification gap** — FR-024 covers malformed rule sets, and a resource-exhausting rule is well-formed. The clarification session spent its five-question quota elsewhere, so the amendment remains outstanding and is carried as a task |
| The verdict model changed shape after design: `limits_hit` became `incomplete` with a discriminated cause | FR-032a requires an unreadable target to yield an inconclusive verdict, and the original model expressed inconclusiveness only through configured bounds. An unreadable file is not a bound anyone set, so the requirement had nowhere machine-readable to live (D14) | Adding a parallel `failures` array was rejected because it splits the FR-004 invariant across two accumulators — two places to forget, in the one check the entire fail-closed posture depends on. This is a breaking change to a contract that has not been published, made deliberately now rather than after embedders depend on it |
| SC-004 previously carried one latency number for two different costs | The consumer is a hook launching the binary per tool call, so observed latency includes process start, rule-set parse, and pattern compilation. Eager compilation of ~80 patterns would plausibly exhaust the budget before any input was read (D4) | **Resolved** — warm per-scan and cold-start budgets are now stated separately (10 ms / 25 ms). No mechanism changed: two-stage matching was already chosen because of this |
