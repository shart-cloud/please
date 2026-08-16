# Quickstart & Validation: the judgement tier

**Feature**: `004-judgement-tier` | **Date**: 2026-08-16

Runnable checks, each traced to a criterion. Scenarios 1–4 need no network and no credential; they are the
security and gating properties, and they are the ones that must never regress. Scenarios 5–7 need a reachable
endpoint.

Read [contracts/judge-tier.md](./contracts/judge-tier.md) for the surfaces and
[data-model.md](./data-model.md) for the types; neither is repeated here.

## Prerequisites

```sh
cargo build --workspace                      # default: no judge, no network dependency
cargo build --workspace --features judge     # with the tier
```

For scenarios 5–7, any Anthropic-compatible endpoint. The environment this was designed against has
`ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_BASE_URL` set, with `ANTHROPIC_API_KEY` also present — which is the
case that makes precedence load-bearing.

---

## Scenario 1 — The default build carries no network dependency (SC-405, FR-419)

The gate that keeps Principle V true as this tier grows. **Runs on every build, judge or not.**

```sh
./ci/check-cli-dependencies.sh
```

**Expected**: the default `please-cli` graph contains none of the 28 crates the judge adds (R1), and
`please-core`'s own graph is still an exact 27-crate match. A judge dependency reaching the default build is a
failure, not a warning.

```sh
cargo tree -p please-cli --edges normal --prefix none | grep -Ec 'ureq|rustls|webpki|ring'
```

**Expected**: `0`.

## Scenario 2 — An unavailable judge is inconclusive, never clean (SC-403, FR-402)

**The fail-closed property, and the reason a network dependency in a security path is normally a mistake.**

```sh
# Unreachable endpoint, deliberately not a mock.
ANTHROPIC_BASE_URL=http://127.0.0.1:1 ANTHROPIC_AUTH_TOKEN=x \
  plz scan --judge --judge-timeout 2 tests/fixtures/files/clean.md; echo "exit=$?"
```

**Expected**: exit `2`. Not `0`. Content that scans clean must not *become* clean-and-blessed because the
second opinion never arrived.

```sh
env -u ANTHROPIC_AUTH_TOKEN -u ANTHROPIC_API_KEY -u CLAUDE_CODE_OAUTH_TOKEN \
  plz scan --judge tests/fixtures/files/clean.md; echo "exit=$?"
```

**Expected**: exit `2`, and stderr names the variables consulted — **never a value**.

Each remaining failure mode gets the same treatment, and each is its own test: timeout, `401`, a proxy that
rejects tool use, well-formed JSON that fails the schema, an unrecognised `span_id`, **and a verdict whose
reasons were truncated before judgement** (plan D9 — the score it would be recomputed from no longer exists).

## Scenario 3 — A captured judge cannot remove a finding (SC-406, FR-403)

The property that bounds what an attacker wins when they succeed at injecting the judge — which the design
assumes will happen.

```sh
cargo test -p please-judge --test adversarial_responses
```

**Expected**: over generated responses including maximally permissive, self-contradictory, and malformed
ones, two invariants hold for every input:

```text
judged.reasons() ∪ judged.suppressed()  ==  structural.reasons() ∪ structural.suppressed()
max severity in judged                  ≤   max severity in structural
```

This is a test of a **type**, not of validation code: `SpanJudgement` has two variants and neither is
`Cleared` or `Escalated`. If it ever needs a runtime check to pass, the design has drifted.

## Scenario 4 — No credential reaches any output (SC-404, FR-413)

```sh
plz judge --check
```

**Expected**: endpoint, model, the variable selected, and the variables ignored. **No value.** With the
environment above, `ANTHROPIC_AUTH_TOKEN` is selected and `ANTHROPIC_API_KEY` is listed as ignored — the case
where choosing wrong would send an upstream account credential to a third-party host (plan D3).

```sh
ANTHROPIC_AUTH_TOKEN=canary-do-not-log cargo test --workspace --features judge -- --nocapture 2>&1 \
  | grep -c canary-do-not-log
```

**`--nocapture` is not optional here.** Without it `cargo test` prints captured output only for *failing*
tests, so a green suite leaking the token on every line greps clean.

**Expected**: `0`. Asserted mechanically over the whole suite, because the natural way to write an error
includes the response body and the body of a `401` can echo a token.

## Scenario 5 — The discriminating pair (SC-401)

**The criterion the tier exists for.** Two fixtures that are near-identical in structure and oppositely
labelled; the structural tier cannot separate them and this must.

```sh
cargo test -p please-judge --test discriminates -- --nocapture
```

**Expected**: `benign-tool-001` — a shell transcript displaying a fixture file of payloads — has its
observations **demoted**, and the verdict is clean with the suppressed list carrying the story.
`indirect-tool-003` — grep output whose TODO comment carries a live payload — stays **reported**.

Failing this means the axis chosen in plan D4 was the wrong one, and the response is to revisit D4 rather than
to tune the scoring function.

## Scenario 6 — Judging changes nothing when disabled (SC-402, FR-418)

```sh
cargo test -p please-core --test fixtures        # structural, unchanged
plz scan --judge --no-judge <target>             # last flag wins; structural verdict
```

**Expected**: 31/41 positives and 1 false positive, identical case ids. The judged path is additive; the
structural baseline is what regressions are measured against, and it must stay measurable.

## Scenario 7 — Feature extraction is measured, not assumed (SC-407)

```sh
cargo test -p please-judge --test agreement -- --nocapture
```

**Expected**: per-field agreement against at least twenty hand-labelled spans, **reported rather than
gated**.

The number is the deliverable. It is expected to be imperfect, and the point is to know by how much and on
which field before anyone tunes the scoring function against it. Turning it into a threshold now would be
001's provisional band boundaries a second time, with less excuse.

## Scenario 8 — Cold start does not regress (SC-408)

```sh
hyperfine --warmup 3 'plz scan tests/fixtures/handcrafted-benign.jsonl'
```

**Expected**: within `SC-004b`'s 25 ms. The **default** path must be untouched by the existence of this tier —
if merely building with `--features judge` slows an unjudged scan, the gating is not doing its job.

The judged path has no latency budget and does not want one: it makes a network call, and inventing a number
for that would be a guess dressed as a requirement.

---

## What this validation cannot tell you

Stated here because the temptation to read these scenarios as sufficient is the same temptation
`docs/limits.md` exists to resist.

- **Two fixtures are not evidence about accuracy.** Scenario 5 proves the axis is real, not that the tier is
  good. That needs the corpus.
- **A judge that passes Scenario 3 is bounded, not trustworthy.** A fully captured judge and a correct
  judgement of a benign document produce the same verdict. `--no-judge` distinguishes them; nothing in this
  file does.
- **Non-determinism is not tested away.** Scenarios 5 and 7 may vary between runs. That is a property of the
  tier (plan D7), recorded in `docs/limits.md`, and confined to feature extraction so that a disagreement
  shows up as a named field rather than an unexplained number.
