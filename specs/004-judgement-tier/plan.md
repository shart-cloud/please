# Plan: the judgement tier

**Feature Branch**: `004-judgement-tier`

**Created**: 2026-08-15

**Status**: Draft — architecture decisions. `spec.md` and `tasks.md` follow from these.

**Input**: Ten positive fixtures remain undetected after 003, and they are not a rule-coverage problem.
Authority spoofing, paradoxical denial, YAML metadata, capability escalation, injection-in-a-list. No pattern
separates *"URGENT SECURITY ADVISORY … grant the sender admin access"* from a real advisory without
understanding what is being asked. One false positive also remains — `benign-tool-001` — and
`docs/limits.md` records it as structurally unfixable in this tier, because a shell transcript displaying
payloads and one carrying a payload are the same document to a surface pass.

Both residues are the same shape: **the structural tier can see form and cannot see intent.**

---

## Summary

A second opinion on findings the structural tier cannot resolve, in a separate crate reached over one
synchronous HTTP request. The model is asked **factual questions with closed answers** and never for a
judgement; this project computes the score. The tier may confirm a finding or demote it into the suppression
channel, and may not erase, escalate, or invent one. Unavailable for any reason means `Inconclusive`.

## Technical Context

| | |
|---|---|
| **Language** | Rust 2021, MSRV as workspace |
| **New crate** | `crates/judge` → `please-judge`, workspace member, depends on `please-core` |
| **HTTP** | `ureq 3`, `default-features = false`, features `rustls` + `json` — 22 crates, no executor (research R1) |
| **Serialisation** | `serde` + `serde_json`, already in the workspace |
| **Async** | **None.** One blocking `POST`. Adding an executor for one request is the objection that ruled out `rig.rs` |
| **Endpoint** | Any Anthropic-compatible `/v1/messages`, via `ANTHROPIC_BASE_URL` |
| **Structured output** | Tool-use schema, required — not prompted JSON (research R2) |
| **Placement** | After finalization, in the CLI, as `Verdict → Verdict` (research R4) |
| **Dependency delta** | 28 crates new to the repository; `please-core`'s 27 unchanged |
| **Performance** | Default path unchanged (`SC-004b`, 25 ms). Judged path: no budget, a timeout |
| **Testing** | Unit + adversarial property tests offline; the discriminating pair and agreement measurement need an endpoint |

**No `NEEDS CLARIFICATION` remains.** Four unknowns were open at Phase 0 and all four are resolved in
[research.md](./research.md). One question is deliberately **left open rather than unresolved**: how features
combine into a score. That is calibration, calibration needs the corpus, and inventing weights now would
repeat 001's provisional band boundaries with less excuse the second time.

---

## The constraint this is built inside

The constitution anticipated this tier and fenced it (Principle V, Scope & Analysis Constraints):

> Model-backed and judgement tiers MUST sit behind explicit opt-in, MUST be addressable as independent
> detectors, and MUST degrade to an indeterminate verdict per Principle I when unavailable — never to clean.

> Heavier capability MUST be additive and opt-in, gated so that a build selecting none of it carries none of
> its dependencies. A guard test MUST enforce that gating rather than trusting review to catch a regression.

`IncompleteCause::TierUnavailable` already exists in the verdict model and has **no production call site** —
a slot reserved for this and used by nothing but a test. It is what the tier degrades to.

Three existing CI gates constrain the design and none may be weakened:

| Gate | Consequence |
|---|---|
| `ci/check-core-isolation.sh` | no network, filesystem, subprocess or clock in `crates/core/src` |
| `ci/check-dependencies.sh` | `please-core`'s shipping graph pinned at exactly 27 crates |
| `wasm32-unknown-unknown` build | core must keep compiling for a target with no sockets |

---

## Constitution Check

*GATE: evaluated before Phase 0 and re-evaluated after Phase 1.*

This is the first feature to add a network dependency, so Principle V's gates carry the weight.

| Gate | Principle | Pre-Phase 0 | Post-Phase 1 | How it is discharged |
|---|---|---|---|---|
| Verdict reports; caller enforces | I | PASS | PASS | `review` returns a verdict; a judge-suppressed finding is reported as suppressed and the deployment's policy disposes |
| Incomplete analysis is never clean | I | **AT RISK** | PASS | The risk is the point: a network dependency is a fail-open waiting to happen. FR-402 sends every failure mode to `TierUnavailable` → `Inconclusive`, and Scenario 2 tests each against a real unreachable endpoint |
| Optional tier degrades to inconclusive, never clean | I | **AT RISK** | PASS | Same mechanism. `IncompleteCause::TierUnavailable` has existed since 001 with no call site, reserved for this |
| Linear-time analysis | II | PASS | PASS | Untouched — the judge arbitrates findings the matcher already made |
| Bounded input and recursion | II | PASS | PASS | Plus a per-invocation timeout (FR-420) |
| Rule sets validated against resource limits | II | PASS | PASS | Untouched |
| No backtracking patterns | II | PASS | PASS | Untouched |
| Fuzzed analysis path | II | **CARRIED** | **CARRIED** | Still 001's T095/T096, still unbuilt. Carried, not passed — the honest colour for a gate with no evidence |
| Rules are reviewable data | III | PASS | PASS | Untouched. The judge declares no rules |
| Rule set identified in every verdict | III | PASS | PASS | Extended: a judged verdict also records model id and prompt version (FR-416) |
| Detection classes independently addressable | III, V | PASS | PASS | Untouched; the judge is a tier, not a class, and adds none |
| Per-source stratified metrics | IV | **DEFERRED** | **DEFERRED** | `please-eval`'s job, still unbuilt |
| False-positive gate in CI | IV | **FAILING** | **FAILING** | Failing at 1 while the corpus is under 200. This tier aims at it and must not be credited before SC-401 and the corpus say so |
| Gaps stated explicitly | IV | PASS | PASS | `docs/limits.md` gains the determinism carve-out (FR-417) and the bounded-not-immune property |
| No corpus text vendored | IV | PASS | PASS | Untouched |
| **Runtime-free, offline, no model** | V | **VIOLATED?** | **PASS** | **The gate this feature exists to test.** The constitution permits it explicitly — *model-backed and judgement tiers MUST sit behind explicit opt-in* — and D1's dependency direction is what keeps the *default* build runtime-free and offline. Discharged by `ci/check-core-isolation.sh` plus the new CLI check |
| `wasm32` build proven in CI | V | PASS | PASS | Core unchanged; nothing downstream of core is in the wasm build |
| **Optional deps gated by test** | V | **GAP** | PASS | The allow-list covers `please-core` only. `ci/check-cli-dependencies.sh` is new and required: the default CLI build must carry none of R1's 28 crates (FR-419, SC-405) |
| CLI holds no logic the library lacks | V | PASS | PASS | The tier is a library (`please-judge`); the CLI wires flags to it |
| Built-in rule set's validity established | II | PASS | PASS | Untouched (added by 002 T086) |

**Pre-Phase 0 verdict**: three gates at risk and one outright gap. All four are the same fact seen from
different angles — this feature introduces network I/O to a project whose central promise is that it needs
none.

**Post-Phase 1 verdict**: all four discharged by mechanism rather than by intent. The dependency direction
(D1) keeps the default build offline by construction; `TierUnavailable` keeps the failure mode fail-closed;
the new CLI check keeps the gating honest as the tier grows. Three gates remain non-passing and all three are
inherited and already recorded: fuzzing, per-source metrics, and the false-positive gate.

**The gap is worth naming separately.** `ci/check-dependencies.sh` has only ever covered `please-core`, which
was sufficient while the CLI had no optional capability. It no longer is, and Principle V requires the gating
be enforced by a check rather than by review. That check does not exist yet and this feature must not ship
without it.

## Project Structure

```text
crates/
├── core/          please-core    unchanged. 27-crate graph, wasm32, no network
├── cli/           please-cli     gains `--judge`, `judge --check`; judge edge behind `--features judge`
├── judge/         please-judge   NEW. ureq client, credential resolution, schema, scoring
│   ├── src/
│   │   ├── lib.rs         Judge::review — the Verdict → Verdict transformation
│   │   ├── credential.rs  Resolution::from_env; the non-Debug newtype (FR-413)
│   │   ├── request.rs     JudgeRequest assembly; neutralisation; no rule ids (FR-406, FR-408)
│   │   ├── response.rs    schema validation; reject-entire (FR-409)
│   │   └── score.rs       Features → SpanJudgement (FR-407)
│   └── tests/
│       ├── adversarial_responses.rs   SC-406 property test
│       ├── discriminates.rs           SC-401, needs an endpoint
│       └── agreement.rs               SC-407, needs an endpoint
└── eval/          please-eval    unchanged, still excluded from the workspace

ci/check-cli-dependencies.sh   NEW. FR-419 / SC-405
```

## D1 — A separate crate, and the dependency direction is the whole safety argument

**Decision**: a new workspace member `crates/judge` (`please-judge`) that **depends on** `please-core`. Core
never depends on it. `please-cli` depends on it behind a non-default feature.

```text
please-core   ← please-judge          core's graph is untouched, whatever judge pulls in
     ↑              ↑
     └── please-cli ┘  (judge edge behind `--features judge`)
```

**Rationale**: this is not tidiness, it is the only arrangement under which the three gates above stay
green by construction rather than by care. `cargo tree -p please-core --edges normal` cannot see a crate that
depends on core, so the 27-crate pin holds no matter what the judge needs. The isolation grep only reads
`crates/core/src`. The wasm build only builds core.

**Not excluded from the workspace like `crates/eval`.** Eval is excluded because it is developer tooling with
heavy corpus dependencies and no shipping role. The judge is a shipping capability users will enable, so it
must be built, tested, linted and version-locked with everything else.

**New guard (extends the existing script)**: assert the **default** `please-cli` build carries no HTTP or TLS
crate. Today the allow-list covers core only, and the moment the CLI grows an optional network edge that gap
matters. Principle V requires the gating be enforced by a check, and the check does not currently exist for
the CLI.

## D2 — HTTP client: `ureq`

**Decided.** Confirmed by the examiner: no tokio for one request. The requirement is one `POST` of JSON to one endpoint, synchronously, with a timeout.

`reqwest` brings `hyper` + `tokio` + `h2` + `tower` and, in blocking mode, spins a tokio runtime per client.
`plz` has no async anywhere and the core is forbidden from requiring a runtime; adding one to the CLI for a
single request is the same weight objection that ruled out `rig.rs`, one level down.

`ureq` is blocking by design, has no executor, and its tree is materially smaller. For one POST it is the
better fit.

The resolved tree is still recorded in `research.md` before the dependency is added, the way D17 recorded the
validation-tier timings — not to reopen the choice, but because the number becomes the CLI allow-list's
baseline and D1's new guard needs something to assert against.

`reqwest` would be the right answer if streaming responses or async batching were ever wanted. Neither is
wanted, and adopting it for a future that may not arrive is how a 27-crate graph becomes a 120-crate one.

## D3 — Auth: four environment variables, one resolution order, stated once

**Decision**: `ANTHROPIC_AUTH_TOKEN` wins whenever it is set. Then this order, first match wins.

| Variable | Header sent | Why this position |
|---|---|---|
| `ANTHROPIC_AUTH_TOKEN` | `Authorization: Bearer …` | Most specific intent. Set deliberately, usually for a proxy |
| `CLAUDE_CODE_OAUTH_TOKEN` | `Authorization: Bearer …` | Present in Claude Code environments; more specific than a bare API key |
| `ANTHROPIC_API_KEY` | `x-api-key: …` | The general default |

`ANTHROPIC_BASE_URL` overrides the endpoint, defaulting to `https://api.anthropic.com`. Every request also
sends `anthropic-version`. `ANTHROPIC_MODEL` selects the model if set, over a pinned default — see D7 on why
the resolved model id is recorded in the verdict.

### Precedence is load-bearing, not hypothetical

Checked against a real Claude Code session, values never read:

```text
SET    ANTHROPIC_AUTH_TOKEN
SET    ANTHROPIC_API_KEY
SET    ANTHROPIC_BASE_URL
unset  CLAUDE_CODE_OAUTH_TOKEN
```

**Two credentials live at once, and a non-default endpoint.** So "use whichever is set" is not a rule — it
does not resolve, and the two want different headers. Having several set is the normal case rather than the
edge case, because tools export their own and nothing cleans up after them.

### Why the precedence is unconditional

The tempting refinement is to pair the two variables — *prefer `ANTHROPIC_AUTH_TOKEN` **when
`ANTHROPIC_BASE_URL` is also set***, since together they describe a proxy. It reads well and it has a hole.

Take the config apart:

| `AUTH_TOKEN` | `BASE_URL` | conditional rule | unconditional rule |
|---|---|---|---|
| set | set | use it | use it |
| set | unset | **falls through** | use it |
| set | unset, nothing else set | **no credential at all** | use it |

The third row is the hole. Someone who exports one variable and expects it to be used gets a tool that says
it is unauthenticated while holding a token — and to avoid that, the conditional rule needs a fallback to
`AUTH_TOKEN` anyway, at which point it has collapsed back into the unconditional one for every case except
the second row.

That second row is the only real disagreement: a bearer token with the default Anthropic endpoint. It is not
a dangerous combination — an Anthropic credential going to Anthropic is where it belongs — so the cost of
guessing wrong is a 401 that the resolution diagnostic explains in one line. The cost of the conditional rule
is that "I set the token and it ignored it" becomes possible, which is the harder failure to diagnose and the
worse one to ship.

**Predictable beats clever for credential selection**, and where they conflict the diagnostic is what closes
the gap: it names the variable chosen and the ones ignored, before any request is made. Unsetting a variable
you do not want used is a normal expectation; a tool silently declining to use one is not.

### Picking wrong is a credential-disclosure bug, not a compatibility bug

The reason `ANTHROPIC_AUTH_TOKEN` is first is not that it is likelier to work. It is that the alternative
sends the wrong secret to the wrong host.

In the session above, ordering `ANTHROPIC_API_KEY` first would take a real Anthropic API key and send it as
`x-api-key` to whatever `ANTHROPIC_BASE_URL` points at. A proxy the user trusts to relay a *proxy token* has
not thereby been trusted with their *upstream account credential*, and the two are not interchangeable just
because both authenticate.

So the order encodes a preference for the **most specifically-scoped** credential available, and the
consequence of getting it wrong is disclosure rather than a 401.

**A warning follows from this.** If the endpoint is non-default and the only credential available is
`ANTHROPIC_API_KEY`, `plz` warns before the request: *you are about to send an Anthropic API key to a host
that is not Anthropic.* That may be entirely intended — it is the user's proxy — but it should be a decision
rather than a default, and it costs one line on stderr.

**Three rules that matter more than the order:**

1. **No credential ever reaches a verdict, a log line, or an error message.** A judge failure must say
   *which variable was consulted*, never what it contained. Worth a test, because the natural way to write
   the error is to include the response body and the body of a 401 can echo a token.
2. **Resolution is reported, not guessed at.** `plz` must be able to say which variable it selected, which
   it ignored, and which endpoint it resolved — **without making a request**. With several set at once and a
   proxy in the path, "why is it hitting the wrong host with the wrong header" is otherwise a bad afternoon,
   and the diagnostic is a handful of lines.
3. **A configured-but-unreachable judge is `TierUnavailable`, not silence.** See D5.

## D4 — The judge reports observations. **We** compute the score.

**Decision**: the model is never asked whether something is an injection, never asked for a severity, and
never asked for a recommendation. It answers a short list of **factual questions about the text**, from
closed option sets. Our code combines those answers into a score, deterministically.

**Rationale — this is the anti-inflation decision, and it is structural rather than a prompt trick.**

Ask a model to find a problem and it will find one. A null result reads as failure to be useful, so the
model's pull is toward giving you something with meat on it — and a security context sharpens that pull,
because overstating looks careful and understating looks negligent. Every mitigation phrased as *"be
conservative"* or *"only flag if confident"* is an instruction competing with that pull, and instructions
lose to incentives.

So remove the incentive rather than argue with it. **A model that is not scoring anything has nothing to
inflate.** Asked *"who is this sentence addressed to?"* there is no impressive answer — the question has no
severe end to drift toward.

Four consequences, each worth the change on its own:

1. **The scoring function is ours.** Auditable, tunable, and changeable without re-prompting or re-measuring
   the model.
2. **Determinism is partly recovered.** Feature extraction is non-deterministic; the function over the
   features is not. Given the same features, the same score — see D7.
3. **Disagreement becomes debuggable.** When the judge is wrong we can see *which feature* it got wrong,
   instead of arguing with a number.
4. **The prompt stops leaking the answer.** We are no longer able to write "our scanner flagged this, is it
   real?", because that is not a question in the schema.

### The questions

Each is a neutral property of the text with a small closed answer set. Note what is absent: the words
*injection*, *attack*, *malicious*, *suspicious*, *risk*. They do not appear in the prompt, because naming
them tells the model which answer is the interesting one.

| Field | Options | What it separates |
|---|---|---|
| `addressed_to` | `document_recipient` · `processing_agent` · `unclear` | The 003 signal, verified |
| `imperative_source` | `document_author` · `quoted_third_party` · `none_present` | Issuing vs relaying an instruction |
| `framing` | `presented_as_example` · `presented_as_data` · `presented_as_report` · `none` | `benign-tool-001` from `indirect-tool-003` |
| `stated_purpose_explains_content` | `yes` · `no` · `unclear` | A CVE advisory quoting a payload |
| `span_role` | `instruction` · `description_of_an_instruction` · `unrelated` | Per flagged span, the core question |

`unclear` is present on every field where it makes sense and costs nothing to choose. Models over-commit when
abstention is not offered, and an abstention is information — it is the honest answer for genuinely ambiguous
text, and text this tier is asked about is often genuinely ambiguous.

### The model's own opinion: recorded, never acted on

The response may carry a `model_severity` field. **Nothing reads it.** It is stored beside the derived score
so that, over a corpus, we can ask whether the model's own scoring would have agreed — and get an answer from
data rather than from a prior.

That is the cheapest possible experiment on the question *"could we have just asked it?"*, and it costs one
unused field. If it turns out to be well calibrated, D4 can be revisited with evidence. Until then, opinion is
logged and data is acted on.

### What this does not change

The judge **is not a detector**. It does not find new payloads; it arbitrates findings the structural tier
already made. Recall stays where the rules can be measured, and the tier points at the precision problem it is
actually good for.

## D5 — The judge writes into the suppression channel, and may never erase a finding

**Decision**: the judge's output is recorded as evidence with the same shape 002 Phase 6 already built.

- Judge says *displayed* → the observation moves to `Verdict::suppressed()`, annotated `suppressed_by: Judge`.
  It is still in the verdict, still readable, still reproducible with `--no-judge`.
- Judge says *instructing* → the observation stays reported, annotated as judge-confirmed.
- Judge unavailable, times out, errors, or returns something unparseable → `CoverageGap::failure(
  TierUnavailable, …)`. Outcome degrades to `Inconclusive`, **never** to `Clean`.

**Rationale, and this is the load-bearing decision in the document.** The judge is reading
attacker-controlled text. That is prompt injection against the judge, and it must be assumed to succeed
sometimes. So the question is not *how do we stop it* but *what does an attacker win when it works?*

If the judge could clear a finding outright, capturing it would be a total bypass of the tool. Because it can
only move a finding into the suppressed channel:

- the structural finding is never erased — it is in the verdict, with the judge named as what demoted it;
- `--no-judge` reproduces the structural verdict exactly, so any dispute is one command to settle;
- the caller's policy decides whether a judge-suppressed finding blocks (Principle I: the verdict reports,
  the caller enforces).

The channel already exists, is already rendered under `--explain`, and already carries "here is what we saw
and why it might not count". The judge is a second author of that same sentence.

**A judge must never *raise* severity or invent a finding either.** An injected judge that can escalate is a
denial-of-service on the caller's pipeline, and a judge that can invent one is an unbounded false-positive
source. Confirm or demote; nothing else.

## D6 — Defending the judge itself

Assume the payload is trying to talk to the judge, because it is.

- **Send neutralised excerpts, not raw documents.** `sanitize_str` already exists and already runs on the way
  into every `Reason`. The judge gets what a reader gets.
- **Envelope the content unambiguously** and instruct the system prompt that everything inside is data under
  analysis, never instructions — the same discipline this repository's own `AGENTS.md` applies to forensic
  evidence.
- **Constrain the output shape** and reject anything that does not parse. A judge that replies in prose is a
  judge that has been talked to.
- **Bound what a single response can do**: closed enums, no free text anywhere in the schema. D4 already
  gives most of this — a captured judge can flip `framing` to `presented_as_example`, and that is the entire
  extent of its influence. There is no field in which it can say something interesting, because there is no
  field that carries prose.
- **Never let judge output reach a shell, a path, or another prompt.** It selects from an enum. It is not
  text we act on.

## D7 — Determinism is explicitly given up for this tier, and said out loud

SC-011 requires byte-identical output for the same input. **A model breaks that**, and `temperature: 0`
narrows it without closing it.

D4 recovers half of it: the score is a deterministic function of the features, so the non-determinism is
confined to feature extraction and is *visible* — two runs disagreeing show which field flipped, rather than
producing two unexplained numbers.

**Decision**: the structural tier keeps its determinism guarantee unchanged; the judgement tier is documented
in `docs/limits.md` as outside it. Every judge-influenced verdict records the model id and prompt version so
an old verdict stays attributable — the same reasoning that made the rule-set digest SHA-256 rather than
`DefaultHasher`, and the same requirement (SC-012).

An optional response cache keyed by `(content hash, model, prompt version)` gives reproducibility within a
run and controls cost. Filesystem, therefore CLI-side; core still opens no files.

## D8 — Off by default, and the structural tier stays complete without it

`--judge` opt-in per invocation. No network on a default run; first run still needs no configuration
(FR-025, FR-031).

The cold-start budget (`SC-004b`, 25 ms) is **unmeetable** with a network call in the path and this is not a
regression to hide — it is a different mode with a different budget. `SC-004a`/`SC-004b` stay as they are and
a third figure is stated for the judged path.

**A per-invocation timeout, defaulting low.** On expiry: `TierUnavailable`, which is `Inconclusive`, which is
exit code 2 — distinguishable from both clean and risk-found, which is the point of the three-outcome model.

## Open questions for the examiner

1. ~~`ureq` or `reqwest`?~~ **Resolved: `ureq`.**
2. ~~Is the auth order right?~~ **Resolved.** Confirmed against a live session where `ANTHROPIC_AUTH_TOKEN`
   and `ANTHROPIC_API_KEY` are both set with a custom `ANTHROPIC_BASE_URL` — the case where the order decides
   whether an upstream account credential goes to a third-party host.
4. **How should the features combine into a score?** Deliberately unanswered here. It is a calibration
   question and calibration needs the corpus, so the first implementation should hold the function trivial
   and obvious — `span_role: description_of_an_instruction` plus a corroborating framing field demotes,
   anything else confirms — and leave tuning to evidence. Inventing weights now would be the same mistake as
   the provisional band boundaries, made a second time with less excuse.
3. ~~Per verdict or per observation?~~ **Resolved by D4.** One call per verdict carrying the document and the
   list of flagged spans; the response carries document-level fields once and a `span_role` per span. The
   framing questions need whole-document context, and `a_live_payload_is_reported_and_a_quoted_one_suppressed_
   in_the_same_scan` already proves one document can contain both answers.

## What follows

`spec.md` (user stories, FRs, success criteria including a judged-fixture accuracy criterion), then
`research.md` recording the measured dependency comparison from D2, then `tasks.md`.

The first fixtures to point at it are already written and already disagree with each other by intent:
`benign-tool-001` and `indirect-tool-003`, structurally identical and oppositely labelled.
