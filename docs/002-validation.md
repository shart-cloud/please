# 002 validation record

Tasks T082–T086. What was checked, mechanically, and what came back.

Written because the lesson from 001 is that a gate can pass on the strength of design intent. Two of 001's
did, and both were false: the plan recorded SC-004 as "Resolved — warm and cold budgets stated separately"
while the spec still carried one number, and the contract described a validation surface that was safe while
the implemented one was not. So each row below names a **mechanism** and a **command**, and "verified" means
the command was run and returned what is recorded.

---

## T082 — the dependency set is unchanged

| | |
|---|---|
| Mechanism | `ci/check-dependencies.sh` against `ci/dependency-allowlist.txt`, plus a diff of the dev graph against `docs/002-dependency-baseline.txt` |
| Command | `./ci/check-dependencies.sh` and `cargo tree --workspace --prefix none --no-dedupe` |
| Result | **Pass.** Shipping graph an exact 27-crate match. Dev graph differs by exactly four entries |

The four are `trybuild` and its subtree — `glob`, `target-triple`, `termcolor` — which the baseline authorises
as the only permitted movement, because two of this feature's guarantees are claims about programs that must
*not* compile and no test that compiles can check one.

Nothing else moved. Notably the `[[bench]]` target added at T031 pulled in nothing: `criterion` was already a
declared dev-dependency and only became reachable from a build target.

## T083 — no test was silently lost (SC-112)

| | |
|---|---|
| Mechanism | diff the full test-name listing against `docs/002-test-inventory-before.txt`, and match every disappearance to a counterpart |
| Command | `cargo test --workspace -- --list` |
| Result | **Pass.** 244 names before, 337 after. 27 disappeared, all 27 accounted for |

    21  moved with their module, leaf name unchanged
         10  detect::pattern::tests::*   ->  matcher::patterns::tests::*
          9  prefilter::tests::*         ->  matcher::prefilter::tests::*
          2  score::tests::*             ->  finalize::score::tests::*
     5  renamed, each with its reason recorded in the phase entries
     1  deleted, with its replacement named

**The check corrected three errors in the hand-maintained ledger**, which is the argument for running it
rather than reading it: two move counts were wrong and the `score::tests` move had not been recorded at all.
A ledger drifts. A ledger plus a mechanical diff does not.

## T084 — accuracy is unchanged in either direction (SC-113)

| | |
|---|---|
| Mechanism | run the fixture report and diff against `docs/002-accuracy-baseline.txt`, including the set of missed case ids |
| Command | `cargo test -p please-core --test fixtures -- --nocapture --test-threads=1` |
| Result | **Pass, against the recorded deviations.** Positives unchanged case-for-case; false positives 8 → 1 as authorised |

    positives      24/41, and the SAME 17 missed ids (set equality checked, not just the count)
    by context     email_body 10/18 · file_read 3/3 · mcp_tool_description 1/3
                   skill_md 1/4 · tool_result 9/13          — identical to baseline
    by difficulty  easy 3/3 · medium 13/20 · hard 8/18       — identical to baseline
    false positives 1 (benign-tool-001)

Two deviations are recorded in the baseline file with their reasons, and T084 compares against those rather
than against the original capture:

1. **Phase 4** moved two scores (`benign-security-prose-003` 90→85, `benign-tool-001` 95→90). Removing the
   `Encoding` class necessarily changes what "distinct class" counts, and the bonus those two lost was
   double-counting one finding delivered by two routes. No outcome changed.
2. **The detection commit** cleared seven false positives. Deliberate work landed at the examiner's
   direction, not drift, and the baseline states that T084 measures against the post-detection figures.

Every refactor phase — 2, 5, 6, 7 — produced output byte-identical to the phase before it. That is the
property SC-113 actually protects, and it held at every step.

## T085 — the quickstart, all ten scenarios

| # | Scenario | Result |
|---|---|---|
| 1 | A resource bomb cannot produce a scanner | **Pass at library level; CLI half not runnable** |
| 2 | Every class is independently addressable | **Pass.** `1 / 1 / 0 / 64` exactly as specified |
| 3 | Cold start does not regress | **Pass.** 3 runs, all ≤ 0.02 s against a 25 ms budget |
| 4 | Validation cost proportional to caller rules | **Pass, measured differently** |
| 5 | No rule is compiled twice | **Pass.** 19/19 in `tests/preparation.rs` |
| 6 | Finalization is the only producer | **Pass.** 26/26 finalization, 3/3 compile-fail cases reject |
| 7 | Suppression observable in one run | **Pass.** Clean verdict *and* the suppressed list |
| 8 | No rule position crosses a seam | **Pass.** 9/9 in `tests/seams.rs` |
| 9 | Accuracy unchanged | **Pass.** See T084 |
| 10 | No test silently disappears | **Pass.** See T083 |

Two do not pass as written, and neither is a pass with an asterisk:

**Scenario 1's CLI invocation cannot be run.** It calls `plz scan --rules /tmp/bomb.toml`, and `plz` has no
`--rules` flag — 001 never built it and documented it as working in two places. The guarantee is established
at the library level across all seven construction paths, which is a wider surface than one flag would be, and
`tests/preparation.rs::every_public_construction_path_rejects_a_resource_bomb` is the check. But the scenario
as written is not runnable and the gap is real: `docs/limits.md` carries it, and the task list carries it as
T077a.

**Scenario 4 was measured by bench rather than by `hyperfine` through the CLI**, for the same reason plus
`hyperfine` not being installed. The bench is better evidence anyway — it isolates validation cost from
everything else the CLI does — and the mechanical assertion is a compiled-pattern count rather than a
duration, because a timing assertion is flaky on a shared runner.

**Scenario 2's ten-of-ten is eight of ten.** `Concealment / encoded` and `Confusable / encoded` are not
addressable by the encoded route, because structural detectors run over the original input only. Closing it is
a detection-capability addition rather than a class-selection fix, it was prototyped and rejected on the
reasoning in `docs/limits.md`, and it is the suite's only `#[ignore]`d test so that it stays greppable rather
than absent.

## T086 — every Constitution Check gate discharged by a passing mechanical check

The lesson from 001, and the reason this file exists. See the table in
[`specs/002-trustworthy-core/plan.md`](../specs/002-trustworthy-core/plan.md), which now names, per gate, the
mechanism, the command, and the commit that discharges it.
