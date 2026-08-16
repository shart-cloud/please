# Feature 004 Constitution Check — discharge audit

T051. Every gate in [`specs/004-judgement-tier/plan.md`](../specs/004-judgement-tier/plan.md)'s Constitution
Check, with the **mechanical check** that discharges it and the commit that made it pass.

A gate discharged by intent is not discharged. Where the evidence is a comment, an argument, or a design
document rather than something that fails, that is said plainly and the gate is not marked green.

```text
audited at   ab59316
date         2026-08-16
```

---

## The four that went in as AT RISK or GAP

These are the ones the plan said to look hardest at, and they are the reason the feature has a Constitution
Check at all: 004 introduces network I/O to a project whose central promise is that it needs none.

### 1. Incomplete analysis is never clean — **PASS**

| | |
|---|---|
| Check | `cargo test -p please-judge --test fail_closed` — 13 modes, each a real socket |
| Commit | `16fd7e9` |
| Fails when | any failure mode produces a verdict without a `TierUnavailable` gap, or loses a finding |

Every mode drives content **that has findings**, because that is where the property bites: a working judge
could demote `benign-tool-001` to clean, so an unavailable one producing the same clean verdict would make
taking the endpoint down a bypass. It does not.

The spec's own scenario was wrong here in two ways and both are corrected in `spec.md` and
`contracts/judge-tier.md` rather than coded around — see `docs/004-validation.md` Scenario 2.

### 2. Optional tier degrades to inconclusive, never clean — **PASS**

Same mechanism, same test. `IncompleteCause::TierUnavailable` had existed since 001 with **no production
call site**, reserved for exactly this; `crates/judge/src/lib.rs::unavailable` is now that site, and every
failure path in the crate routes through it so there is one answer rather than one per caller.

### 3. Runtime-free, offline, no model — **PASS**

| | |
|---|---|
| Check | `./ci/check-cli-dependencies.sh` and `./ci/check-dependencies.sh` and `./ci/check-core-isolation.sh` |
| Commit | `9f11282` |
| Fails when | the default `plz` graph gains any crate, or any HTTP/TLS crate by name, or `--features judge` **lacks** one |

The default build carries none of the 19 crates the tier adds. `please-core` is untouched at exactly 27, and
`cargo tree -p please-core` structurally cannot see a crate that depends on core — which is the whole of D1
and the reason this holds by construction rather than by care.

### 4. Optional deps gated by test — **PASS.** This was the outright GAP.

| | |
|---|---|
| Check | `./ci/check-cli-dependencies.sh`, wired into CI as its own step |
| Commit | `9f11282` |
| Fails when | the exact-match allow-list drifts, an HTTP/TLS crate appears by name, **or the feature build stops pulling one** |

`ci/check-dependencies.sh` had only ever covered `please-core`, which was sufficient while the CLI had no
optional capability. Principle V requires the gating be enforced by a check rather than by review, and that
check did not exist.

**The third assertion is the one worth noting**, and it is not in the task description. A gate that only
checks for *absence* passes trivially the day the feature flag breaks, misspells, or gets dropped from
`Cargo.toml` — and then reports success while the capability it guards does not exist. Absence is only
evidence of gating if the feature build differs.

---

## The gates that were already passing, and stayed

| Gate | Principle | Check | Commit |
|---|---|---|---|
| Verdict reports; caller enforces | I | `judge_cli.rs` — a judge-suppressed finding is *reported as suppressed* | `072c26c` |
| Linear-time analysis | II | untouched; the judge arbitrates findings the matcher already made | — |
| Bounded input and recursion | II | `fail_closed.rs::a_timeout_is_inconclusive`, `…oversized_document…` | `16fd7e9` |
| Rule sets validated against resource limits | II | untouched | — |
| No backtracking patterns | II | untouched; the judge declares no patterns | — |
| Rules are reviewable data | III | untouched; the judge declares no rules | — |
| Rule set identified in every verdict | III | extended — `judge_cli.rs::…shows_which_answer_drove…` asserts model id and prompt version | `072c26c` |
| Detection classes independently addressable | III, V | untouched; the judge is a tier, not a class, and adds none | — |
| Gaps stated explicitly | IV | `docs/limits.md` gains three sections | `ab59316` |
| No corpus text vendored | IV | untouched | — |
| `wasm32` build proven in CI | V | `cargo build -p please-core --target wasm32-unknown-unknown` | `9f11282` |
| CLI holds no logic the library lacks | V | the tier is `please-judge`; `main.rs` wires flags to `Judge::review` | `16fd7e9` |
| Built-in rule set's validity established | II | untouched (002 T086) | — |

---

## Still not passing, and none of it is 004's

Carried forward unchanged. Listing them green would be the failure mode this document exists to prevent.

### Fuzzed analysis path — **CARRIED**

Still 001's T095/T096, still unbuilt. **Carried, not passed** — the honest colour for a gate with no
evidence. 004 adds a new parser (`crates/judge/src/response.rs`) that reads attacker-influenced JSON, so the
case for this gate is now marginally stronger than it was, not weaker. The parser is `serde` with
`deny_unknown_fields` over closed enums rather than hand-rolled, which narrows the surface without
discharging the gate.

### Per-source stratified metrics — **DEFERRED**

`please-eval`'s job, still unbuilt. SC-407's agreement measurement is **not** this and must not be mistaken
for it: 21 hand-labelled cases by one person is a calibration baseline, not a corpus metric.

### False-positive gate in CI — **FAILING**

Still failing at 1 while the corpus is under 200. The plan said this tier aims at it and **must not be
credited before SC-401 and the corpus say so**. SC-401 now says so; the corpus does not exist. So:

- **unjudged**, `benign-tool-001` is still a false positive and `docs/004-accuracy-baseline.txt` is
  unchanged — 31/41, one FP, the same ten missed ids;
- **judged**, it demotes to clean, measured 5/5.

The second is not a corpus result and the gate is not moved. `docs/limits.md` states all three limits the
5/5 does not convey.

---

## One gate this feature added to itself

**No credential in any output** — `./ci/check-no-credential-leak.sh`, commit `906f570`.

Not in the plan's table because FR-413 arrived as a requirement rather than a constitutional gate, and it
earns a place here because it is the one check in this feature that was **vacuous three times before it
worked**. The failure modes are recorded in the script: `cargo test` captures passing output, no test called
`from_env` so the canary reached no code, and the suite fail-fasts before reaching `please-judge`.

A check that cannot fail is not a check, and this one could not, twice, while looking like it worked.
