# Feature 004 validation record

Every scenario in [`specs/004-judgement-tier/quickstart.md`](../specs/004-judgement-tier/quickstart.md),
run and recorded — **including the ones that could not be run, and why** (T050).

```text
date        2026-08-16
commit      ab59316  docs(004): phase 8 part one
toolchain   cargo 1.96.0 (30a34c682 2026-05-25)
endpoint    an Anthropic-compatible proxy via ANTHROPIC_BASE_URL
model       claude-sonnet-4-5 (default; ANTHROPIC_MODEL unset)
prompt      2026-08-16.1
```

---

## Scenario 1 — The default build carries no network dependency (SC-405, FR-419)

**PASS.**

```text
$ ./ci/check-cli-dependencies.sh
cli dependency allow-list: exact match (50 crates), no HTTP or TLS crate     exit 0

$ cargo tree -p please-cli --edges normal --prefix none | grep -Ec 'ureq|rustls|webpki|ring'
0

$ cargo tree -p please-cli --edges normal --prefix none --features judge | grep -Ec 'ureq|rustls|webpki|ring'
11
```

The third command is not in the quickstart and is the half that makes the first two mean anything. A gate
that only checks for absence passes trivially the day the feature flag breaks, and then reports success
while the capability it guards does not exist. The script asserts all three directions.

`please-core` is unchanged at 27 crates, `ci/check-core-isolation.sh` is clean, and `wasm32-unknown-unknown`
still builds.

## Scenario 2 — An unavailable judge is inconclusive, never clean (SC-403, FR-402)

**PASS, with the scenario itself corrected twice.** 13 failure modes, each against a real socket rather than
a mock: unreachable endpoint, no credential, timeout, HTTP 401, a 401 whose body echoes a token, a response
in prose, malformed JSON, an unknown field, an unknown enum value, an unknown `span_id`, a missing span, an
oversized document, and a verdict with no observations.

```text
$ cargo test -p please-judge --test fail_closed
test result: ok. 13 passed

$ ANTHROPIC_BASE_URL=http://127.0.0.1:1 ANTHROPIC_AUTH_TOKEN=x \
    plz scan --judge --judge-timeout 2 <file with findings>
  unexamined: tier_unavailable (http://127.0.0.1:1 could not be reached: io: Connection refused)
exit=1
```

**Two corrections to the scenario as written**, both recorded in `spec.md` and
`contracts/judge-tier.md`:

- It used **clean content**, which never reaches the judge at all: FR-404 makes no request when a verdict
  has no observations, so an unreachable endpoint costs nothing and the verdict stays `Clean` at exit `0`.
  US3 Scenario 1 contradicted US1 Scenario 3 on this point. The guarantee that carries the constitutional
  requirement is the restated one — *a verdict **with** observations never becomes `Clean`* — and it is the
  stronger claim, because `benign-tool-001` is a verdict a working judge demotes to clean.
- It expected exit **`2`**, which is unreachable through this tier. Every verdict the judge can fail on has
  findings, and `risk_found` outranks `inconclusive`. A failed judgement exits `1` or `3` carrying a visible
  gap. The guarantee was always "never `0`".

## Scenario 3 — A captured judge cannot remove a finding (SC-406, FR-403)

**PASS.**

```text
$ cargo test -p please-judge --test adversarial_responses
test result: ok. 5 passed
```

A property test over generated reports — empty, maximally permissive, self-contradictory, naming
observations that do not exist — plus four hand-written cases. Each invariant was **verified by mutation**
rather than by being green on first run:

| mutation | caught by |
|---|---|
| contradiction resolved with `=` instead of `\|=` | the contradiction test, alone |
| a demoted reason dropped instead of moved | four of five, including the property |
| out-of-range report applied in part | the refusal test, alone |

## Scenario 4 — No credential reaches any output (SC-404, FR-413)

**PASS.**

```text
$ plz judge --check
  endpoint   https://<proxy>                        (ANTHROPIC_BASE_URL)
  model      claude-sonnet-4-5                      (default; ANTHROPIC_MODEL unset)
  credential ANTHROPIC_AUTH_TOKEN                   →  Authorization: Bearer
  ignored    CLAUDE_CODE_OAUTH_TOKEN                (unset)
             ANTHROPIC_API_KEY                      (set; lower precedence)

$ ./ci/check-no-credential-leak.sh
credential leak check: no canary value in any test output (758 lines scanned)
```

This is the live configuration plan D3 was written against: two credentials set at once with a non-default
endpoint, where choosing wrong sends an upstream account credential to a third-party host.

**The leak check took three attempts to become real**, and the failures are recorded in `ci/check-no-credential-leak.sh`
because each looked fine:

1. as the quickstart specified it, `cargo test` captures stdout and prints it only for *failing* tests — a
   green suite leaking on every line greps clean. Needs `--nocapture`;
2. with `--nocapture` it still missed a deliberately-leaking `Debug`, because no test called `from_env` and
   the canary reached no code path at all;
3. it *still* missed it, because `cargo test` stops after the first failing test binary and this
   repository's fixture tests are red at the 004 baseline by design — the run never reached `please-judge`.
   Needs `--no-fail-fast`. Output went from 336 lines scanned to 758.

Only after all three does mutating `Debug` to print the value fail the check.

## Scenario 5 — The discriminating pair (SC-401)

**PASS**, and it did not at first.

```text
$ cargo test -p please-judge --test discriminates
test result: ok. 3 passed

benign-tool-001    4 observations → 0 reported, 4 suppressed by the judge, verdict Clean
indirect-tool-003  1 observation  → 1 reported, verdict RiskFound
```

Stability, five rounds each: **5/5 correct both ways**.

The route here is the substance of the feature and is written up in plan D4a. In short: the original
question set answered **identically** for both fixtures, correctly, because at document scale the two
transcripts genuinely are the same document. The separating question is one level down — *is this excerpt
what the document set out to show, or a passenger inside it?* — and the final fix was one line of the tool's
`description`, since naming the document before the excerpts frames every excerpt as part of it.

## Scenario 6 — Judging changes nothing when disabled (SC-402, FR-418)

**PASS.**

```text
$ cargo test -p please-core --test fixtures
31/41 positives detected; 10 missed
1 false positive(s): benign-tool-001
```

Identical to `docs/004-accuracy-baseline.txt`: same counts, same ten case ids, same single false positive.
Unchanged whether or not the binary was built with `--features judge`.

`--no-judge` reproduces the structural verdict byte-identically, and `--judge --no-judge` does too —
last flag wins, asserted in both orderings.

## Scenario 7 — Feature extraction is measured, not assumed (SC-407)

**PASS — reported, not gated.** 21 hand-labelled cases, 20 spans.

| field | agreed | rate |
|---|---|---|
| `span_relation_to_document` | 12 / 12 | **100%** |
| `stated_purpose_explains_content` | 15 / 15 | 100% |
| `framing` | 14 / 15 | 93% |
| `addressed_to` | 9 / 11 | 82% |
| `imperative_source` | 12 / 15 | 80% |
| `span_role` | 14 / 20 | **70%** |

The field the tier's accuracy rests on is the most reliable one measured, which is the reassuring half. The
unreassuring half is `span_role`, whose disagreements all run the same direction and may mean the **labels**
are wrong rather than the model — in which case `span_role` contributes much less than D4 assumed, and the
corroboration argument is weaker than it looks. Recorded in the test output and in `docs/limits.md`; the fix
is more labelled data, not a change to the scoring function.

## Scenario 8 — Cold start does not regress (SC-408)

**PASS.**

```text
default build            6.0 ms per run (20 runs, release, 3 warm-up)
built --features judge   5.7 ms per run
```

Against `SC-004b`'s 25 ms. `hyperfine` was not available, so this is a shell loop over 20 runs after 3
warm-ups — cruder than the quickstart specifies and sufficient for the claim being made, which is that the
two builds do not differ. They do not.

---

## What this validation cannot tell you

Restated from the quickstart because the temptation to read these results as sufficient is exactly what
`docs/limits.md` exists to resist.

- **Two fixtures are not evidence about accuracy.** Scenario 5 proves the axis is real, not that the tier is
  good. That needs the corpus.
- **A judge that passes Scenario 3 is bounded, not trustworthy.** A fully captured judge and a correct
  judgement of a benign document produce byte-identical verdicts. `--no-judge` distinguishes them; nothing
  in this file does.
- **Twenty spans is a small number.** Scenario 7's rates have wide error bars and one person wrote every
  label.
- **Non-determinism is not tested away.** Scenarios 5 and 7 may vary between runs. It is a property of the
  tier, confined by plan D4 to feature extraction so a disagreement shows up as a named field.
- **Nothing here was run against a hostile endpoint.** Every failure mode was a local socket behaving
  badly, not a proxy actively trying to break the parser.
