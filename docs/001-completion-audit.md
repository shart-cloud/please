# Feature 001 — completion audit

> **Updated after the work.** `--format json`, `--rules` and `--disable-rule` are **done** — commits
> `1ec0a26`, `6249999`, `6f688b8`. The task list is now 95 done / **21 open**, and every one of the 21 is
> genuinely open. Sections 1 and 2 below are kept as the record of what was found and why it was invisible;
> section 3 onward is what is still outstanding. See "What landed" at the end.

What `specs/001-structural-detection-cli/tasks.md` still has unchecked, against **what is actually true of
the code**. Written at `ffe478d`, after 004 shipped.

The two do not match in either direction. 53 tasks are unchecked; most of their *behaviour* exists, built by
002/003/004 under different file names and never ticked back. But a handful are genuinely missing, and two
of those are user-visible capabilities the CLI contract advertises and the binary rejects.

**Checkbox state is not evidence.** Every claim below was checked against the filesystem, the test suite, or
`plz --help`.

---

## The short version

| Story | Priority | Was | Now |
|---|---|---|---|
| US1 — check an artifact before trusting it | P1 | Complete | **Complete** |
| US2 — gate an agent's tool call automatically | P2 | Half — no `--format json` | **Complete.** JSON output, validated against the schema on every run |
| US3 — hostile and oversized input handled honestly | P3 | Mostly | **Mostly** — unchanged. Fuzzing, the scaling benchmark and the self-steering tests are still absent |
| US4 — tune and extend detection without a rebuild | P4 | Library yes, CLI no | **Complete.** Both flags reach the binary |

---

## 1. What a user hits first: two advertised flags that do not exist

`specs/001-structural-detection-cli/contracts/cli.md` lists ten options. **Seven are implemented. Three are
not**, and the binary rejects them as unknown arguments:

```text
$ plz scan --format json
error: unexpected argument '--format' found

$ plz scan --rules ./team.toml
error: unexpected argument '--rules' found
```

### `--format json` — **entirely absent** (T065, T068, T069, T070)

This is the larger gap, because **US2's first acceptance scenario is about it**: *"a machine-readable result
is written to standard output"*. There is no machine-readable output at all. `plz` emits human prose only.

What is missing, in order:

- **`serde` derives on the verdict types.** The `serde` feature exists on `please-core`, `please-cli`
  enables it, and **nothing in `crates/core/src` derives `Serialize`**. The feature currently buys nothing.
- **A JSON renderer.** `crates/cli/src/render/json.rs` does not exist.
- **`--format` itself**, including the TTY-dependent default the contract specifies — `human` when stdout is
  a terminal, `json` otherwise. Worth questioning before implementing: a default that changes when output is
  piped means a hook and a human see different things from the same command, which is usually a bug factory.
- **The schema contract test.** `specs/001-structural-detection-cli/contracts/verdict.schema.json` exists,
  is maintained (004 amended it), and **nothing validates against it**. It has never been checked against
  real output because there is no real output.

Note the knock-on: 004 amended that schema to add `judge` and widen `suppressed_by`, so the schema now
describes a shape no code produces and no test checks.

### `--rules <PATH>` and `--disable-rule <ID>` — **library complete, CLI missing** (T102, T103)

This one is nearly free, and that is the surprising part. Everything underneath works and is thoroughly
tested — `crates/core/tests/ruleset_load.rs` has 38 tests covering additions, suppressions, replacement
reporting, unknown-suppression rejection, digest changes, and delta validation:

```rust
Engine::builder()
    .add_ruleset(team_rules)      // works
    .disable("override.polite")   // works, errors on a typo
    .build()                      // works, validates only the delta
```

`EngineBuilder` is public. `Engine::from_toml` is public. `crates/cli/src/main.rs` calls
`Engine::builtin()` unconditionally and never touches either.

So **US4's whole point — "no rebuild of the tool" — is unreachable from the tool.** An embedder gets it; a
`plz` user does not. SC-010 (*"a team can suppress one built-in rule and add one of their own"*) is
satisfied only if the team writes Rust.

T104 (replacement reporting, unknown-suppression rejection) is **already done** in
`crates/core/src/ruleset/mod.rs` and tested. T105 (`--classes`) and T106 (`--no-suppress-in-quotes`) are
**both done and shipped**. The gap is two flags and the file read behind them.

---

## 2. Tasks whose behaviour exists under a different name

These are unchecked and **done**. The task named a file that was never created; the behaviour landed
elsewhere, mostly during 002. Listing them so nobody rebuilds them.

| Task | Named file | Actually covered by |
|---|---|---|
| T066 stream discipline | `cli/tests/contract.rs` | `cli.rs::diagnostics_go_to_stderr_and_never_to_stdout` |
| T067 six exit codes reachable and distinct | `cli/tests/exit_codes.rs` | `cli.rs::every_documented_exit_code_is_distinct` — **rewritten at 002 T047 to drive the binary** rather than assert six literals are different from each other |
| T068 determinism | `cli/tests/determinism.rs` | `cli.rs::repeated_runs_over_a_directory_produce_identical_output`, `…does_not_vary_with_the_working_directory`, `scan.rs::the_same_input_yields_the_same_verdict` |
| T071 exit-code mapping | `cli/src/exit.rs` | `main.rs::exit_code`, all six codes present |
| T072 warnings never reach stdout | `cli/src/main.rs` | done; tested as T066 above |
| T073 multi-target precedence | `cli/src/main.rs` | `main.rs::exit_code` implements `risk_found > inconclusive > clean`; tested |
| T078 every bound enforced and reported | `core/tests/bounds.rs` | all five, spread across `scan.rs` (input size, match saturation, reason truncation), `finalization.rs` (excerpt length), and `decode::tests` (depth, cycles) |
| T079 oversized → inconclusive | `core/tests/bounds.rs` | `scan.rs::oversized_input_is_inconclusive_and_never_clean`, `…is_not_analysed_at_all` |
| T080 failed rule-set load never clean | `ruleset_load.rs` | `a_bomb_that_parsed_cannot_become_a_scanner`, `one_bad_rule_rejects_the_whole_set` |
| T084 unreadable target in a walk | `cli/tests/walk.rs` | `cli.rs::a_directory_is_walked_and_each_target_reported`; `finalization.rs::an_unreadable_target_is_inconclusive_and_never_skipped` |
| T088–T092 bound implementations | various | all implemented and exercised |
| T098–T101 rule resolution | `ruleset_load.rs` | 38 tests, including `an_addition_replacing_a_builtin_is_reported` and `suppressing_an_unknown_rule_is_an_error_not_a_no_op` |
| T104 replacement/suppression reporting | `ruleset/mod.rs` | done |
| T105 `--classes` | `args.rs` | done, shipped, tested |
| T106 `--no-suppress-in-quotes` | `args.rs` | done, shipped, tested |
| T108 amend FR-024 | `spec.md` | 002 addressed rule-set resource limits |
| T111 complete `docs/limits.md` | — | exists, 437 lines, extended by 002/003/004 |
| T112 complete `docs/attribution.md` | — | exists; 004 added its section |

**These should be ticked, not rebuilt.** The cost of leaving them unticked is exactly what happened here: a
53-item list that reads as "half the feature is missing" when the real number is much smaller.

---

## 3. Genuinely missing, and not user-visible

Real gaps. None of them affect someone using the binary today; all of them are things the spec promised as
evidence.

### Measurement infrastructure — the largest cluster

| Task | Missing | Blocks |
|---|---|---|
| T085, T086 | `crates/core/fuzz/` does not exist — no fuzz targets at all | **SC-006** (one million inputs, no crash) |
| T095, T096 | fuzz smoke job, scheduled campaign workflow | SC-006; the constitution's *fuzzed analysis path* gate, still `CARRIED` after four features |
| T087 | `crates/core/benches/scaling.rs` — no growth-exponent measurement | **SC-005** (linear growth across four orders of magnitude) |
| T093 | throughput benchmark, p95 within 10 ms at 4 KB, ≥10 MB/s | **SC-004a** |
| T094 | cold-start measurement as a test | **SC-004b** — measured ad hoc during 004 (~6 ms) but not pinned |

Only `benches/preparation.rs` exists. **SC-004a, SC-005 and SC-006 are unverified**, and the constitution's
fuzzing gate has been carried since 001 on that basis.

### FR-020 — content cannot steer the analysis (T081, T082)

`crates/core/tests/no_self_steering.rs` does not exist, and nothing else tests either half:

- **FR-020a**: an input containing text that resembles a rule definition, a configuration directive, or an
  instruction addressed to the scanner must produce the same verdict as the same input with that text as
  inert prose.
- **FR-020b**: per-input verdicts must be identical regardless of scan order or what was scanned before.

This is a **security property with no test**, and it is squarely in the threat model — the scanner reads
attacker-controlled text, and "can the content talk to the scanner?" is the same question 004 asked about
the judge. Of everything in this section, this is the one I would do first.

### T083 — concurrency

`contracts/core-api.md` claims `Engine` is `Send + Sync` and that lazy pattern compilation makes no verdict
depend on scan history. Neither is tested. Lazy compilation is real (`pattern_is_compiled` exists to observe
it), which makes the claim load-bearing rather than incidental.

### SC-003 — the hard-negative corpus (T043)

**17 benign fixtures against a stated minimum of 200.** The fixture suite says so itself:

```text
note: 17/200 benign cases. The SC-003 gate is not yet meaningful; current
      false-positive rate 5.9% over 17 cases is informational only.
```

This is the single number most of the project's deferred claims point at. The constitution's false-positive
gate is `FAILING` because of it; `docs/limits.md` defers to it repeatedly; 004 could not credit SC-401
against it. It is also the most work of anything on this list.

T076 (adversarial fixtures) and T077 (resource-exhausting rule sets) are partly there — `tests/fixtures/rules/bomb.toml`
exists and is tested; `tests/fixtures/adversarial/` holds only a README.

---

## 4. Documentation

| Task | Missing | Note |
|---|---|---|
| T110 | **`README.md` does not exist** | The repository has no README at all. For a tool whose accuracy claims need qualifying, the absence is worse than a thin one — SC-009 asks an integrator to wire this into a hook, and there is nothing to read |
| T074, T075 | `examples/hooks/pre-tool.sh`, and the integration contract in the README | **SC-009** is unverified. US2's *"a sample hook script exercising the contract demonstrates it end to end"* has nothing behind it |
| T107 | `docs/rules.md` — rule format, resolution order, worked override example | Blocked behind `--rules` being reachable; pointless to document a flag that does not parse |
| T113 | rustdoc on every public item in `crates/core/src` | Coverage is actually high — most public items are documented at length. Worth an audit pass rather than a rewrite |
| T114 | `docs/walkthrough-log.md` | **SC-001a**: once per release, a reader not involved in building the tool scans prepared content and states what was found. Never run, never recorded |
| T115 | run all eight 001 quickstart scenarios and record | 002 and 004 have validation records; 001 does not |
| T116 | discharge audit for 001's Constitution Check | 004 has one (`docs/004-constitution-audit.md`); 001 does not |
| T109 | MSRV pinned and asserted in CI | `rust-version = "1.85"` is in `Cargo.toml`; **no CI job verifies it**, so it is a claim rather than a constraint |

---

## Suggested order

Reasoning rather than a schedule.

1. **`--rules` / `--disable-rule`** (T102, T103, T107). Smallest gap with the largest ratio: the engine
   already does all of it, correctly and with 38 tests. Two flags and a file read make US4 real for anyone
   not writing Rust.
2. **`--format json`** (T069, T070, T065, T068). Larger, and it is what US2 is *for*. Also the only thing
   that makes `contracts/verdict.schema.json` a contract instead of a document — and that schema is now two
   features out of date with nothing to catch it.
3. **`README.md` and the hook script** (T110, T074, T075). SC-009 is the product's main distribution path
   and currently has no on-ramp. Cheap.
4. **FR-020 self-steering tests** (T081, T082). A security property with no test, in a tool whose input is
   hostile by assumption.
5. **Fuzzing and the scaling benchmark** (T085–T087, T093, T095, T096). Discharges the constitution gate
   that has been carried since 001 and unblocks SC-004a/005/006.
6. **The 200-fixture corpus** (T043). Most work, blocks the most claims, and is the one thing on this list
   that cannot be done by writing code.

And separately, **tick the ~18 tasks in section 2**, so the list stops overstating what is left.


---

## What landed

Three commits, and one of them is a bug fix nobody asked for.

### `1ec0a26` — the schema had drifted from the type for two features

Written first, because with `additionalProperties: false` on every object a *correct* serialiser fails
validation against the schema as it stood. Three gaps:

| | |
|---|---|
| `suppressed`, `suppressions_truncated` | 002 added both to `Verdict`; the schema never learned. Flagged in the data-model at the time and left for a 002 amendment that never came |
| `judge_report.judgements[].relation` | 004's plan D4a added it — *"the field that decides the case"* — and amended the prose contract and the data model but not the schema |
| `model_severity` | Confirmed deliberately absent (FR-410). The serialiser skips it and the schema is right to reject it |

All three were invisible for one reason: **nothing had ever validated output against this file.** It was
maintained across four features as a document. The first thing a contract does is find where it drifted.

### `6249999` — `--rules` and `--disable-rule` (US4)

Both repeatable. `--rules` layers in argument order; `--disable-rule` applies last. The engine already did
all of it, so the substance was the exit-code split: a caller's malformed TOML is **64**, the built-in rule
set failing to load stays **70**. There had been one arm returning 70 for both, so a typo in someone's rule
file announced itself as an internal error worth filing a bug about.

`docs/rules.md` documents the format and resolution order.

### `6f688b8` — `--format json` (US2)

Derived in `please-core` behind the existing `serde` feature, with every enum serialising through its own
`as_str()` rather than `rename_all`. That makes "wire names are kept beside the variants so the serialised
form cannot drift" structurally true instead of a convention — and it is the only thing that works for
`SuppressedBy`, whose newtype variant `rename_all` would render as an object where the schema wants a flat
string.

`crates/cli/tests/contract.rs` validates every fixture's output against the real schema file, using a
`jsonschema` dev-dependency. Verified by mutation: an added field and a renamed field both fail it.

**Two things this shook out that no test would have:**

- **The TTY-dependent default is real.** `--format` defaults to `json` when stdout is not a terminal, and a
  test harness captures stdout through a pipe — so every existing CLI test asserting on prose silently
  started reading JSON. They now pin `--format human`, which they should have done anyway. This is the cost
  of the contracted default, and it is worth knowing it is not hypothetical.
- **An EPIPE race that looked like a flake.** The usage-error tests exit *before* reading stdin, so the
  parent's `write_all` hits a closed pipe. Running one test binary the parent usually wins the race;
  running `--workspace` with every binary competing for cores it does not.

---

## Still open: 21 tasks

Unchanged in substance from sections 3 and 4 above, and now the whole list rather than a third of it.

| | Tasks | Why it matters |
|---|---|---|
| **The corpus** | T043, T076, T077 | 17 hard-negative fixtures against a stated 200. The number most of the project's deferred claims point at |
| **Measurement** | T085–T087, T093–T096 | No fuzz targets at all, no scaling or throughput benchmark. SC-004a, SC-005, SC-006 unverified; the constitution's fuzzing gate has been `CARRIED` for four features |
| **FR-020 self-steering** | T081, T082 | A security property with no test, in a tool whose input is hostile by assumption. **The one I would do first** |
| **Concurrency** | T083 | `core-api.md` claims `Engine` is `Send + Sync`; nothing tests it |
| **On-ramp** | T074, T075, T110 | Still no `README.md` and no hook script. SC-009 is the product's main distribution path |
| **Process** | T109, T113, T114, T115, T116 | MSRV asserted in CI, a rustdoc audit, the walkthrough log, 001's quickstart validation and constitution audit |

The ordering advice from the original audit stands for what is left: **FR-020 first** — it is the only
security property on the list — then fuzzing and benchmarks to discharge the constitution gate, then the
README, then the corpus.
