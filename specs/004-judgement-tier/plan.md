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

## D2 — HTTP client: recommend `ureq`, not `reqwest`

**Decision to confirm.** The requirement is one `POST` of JSON to one endpoint, synchronously, with a timeout.

`reqwest` brings `hyper` + `tokio` + `h2` + `tower` and, in blocking mode, spins a tokio runtime per client.
`plz` has no async anywhere and the core is forbidden from requiring a runtime; adding one to the CLI for a
single request is the same weight objection that ruled out `rig.rs`, one level down.

`ureq` is blocking by design, has no executor, and its tree is materially smaller. For one POST it is the
better fit.

**We should measure rather than assume before committing** — dependency weight is a first-class concern in
this project and the allow-list exists to keep it so. Concretely: `cargo tree` both, compare, record the
numbers in `research.md` the way D17 recorded the validation-tier timings.

`reqwest` remains the right answer if streaming responses or async batching are ever wanted. Neither is
wanted now, and adopting it for a future that may not arrive is how a 27-crate graph becomes a 120-crate one.

## D3 — Auth: four environment variables, one resolution order, stated once

**Decision**: resolve in this order, first match wins.

| Variable | Header sent | Why this position |
|---|---|---|
| `ANTHROPIC_AUTH_TOKEN` | `Authorization: Bearer …` | Most specific intent. Set deliberately, usually for a proxy |
| `CLAUDE_CODE_OAUTH_TOKEN` | `Authorization: Bearer …` | Present in Claude Code environments; more specific than a bare API key |
| `ANTHROPIC_API_KEY` | `x-api-key: …` | The general default |

`ANTHROPIC_BASE_URL` overrides the endpoint, defaulting to `https://api.anthropic.com`. Every request also
sends `anthropic-version`.

**Three rules that matter more than the order:**

1. **No credential ever reaches a verdict, a log line, or an error message.** A judge failure must say
   *which variable was consulted*, never what it contained. Worth a test, because the natural way to write
   the error is to include the response body and the body of a 401 can echo a token.
2. **Resolution is reported, not guessed at.** `plz` must be able to say which variable it used and which
   endpoint it resolved, without making a request. Chasing "why is it hitting the wrong host" through four
   environment variables is otherwise a bad afternoon.
3. **A configured-but-unreachable judge is `TierUnavailable`, not silence.** See D5.

## D4 — What the judge is asked: one narrow question

**Decision**: the judge is not asked *"is this malicious?"*. It is asked the question the structural tier
provably cannot answer:

> **Is this content instructing the agent, or displaying/describing an instruction?**

**Rationale**: it is the exact axis of every remaining failure in both directions. `benign-tool-001` displays
payloads; `indirect-tool-003` carries one; they are byte-similar. `benign-addressed-00N` quote agent-addressed
markers; `indirect-tool-001` uses one. A narrow question is also markedly harder to injection-hijack than an
open one, and far easier to evaluate — we can build a fixture set with a known answer per case, which we
cannot do for "is this bad".

Scope-limiting consequence: the judge **is not a detector**. It does not find new payloads. It arbitrates
findings the structural tier already made. That keeps the recall problem where the rules can be measured, and
points the tier at the precision problem it is actually good for.

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
- **Bound what a single response can do**: one verdict per observation, from a closed set. There is no field
  in which a captured judge can say something interesting.
- **Never let judge output reach a shell, a path, or another prompt.** It selects from an enum. It is not
  text we act on.

## D7 — Determinism is explicitly given up for this tier, and said out loud

SC-011 requires byte-identical output for the same input. **A model breaks that**, and `temperature: 0`
narrows it without closing it.

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

1. **`ureq` or `reqwest`?** (D2) Recommend `ureq`, measure first. Your call, since you have used `reqwest`
   before and familiarity is worth something.
2. **Is the auth order in D3 right for your proxy setup?** I put `ANTHROPIC_AUTH_TOKEN` first on the reasoning
   that a proxy token is the most deliberate signal.
3. **Does the judge get one call per verdict, or one per observation?** Per-verdict is cheaper and gives the
   model whole-document context, which the displayed-versus-live question probably needs. Per-observation is
   more precise in attribution and more resistant to one injected answer contaminating every finding.
   Leaning per-verdict with per-observation answers in the response.

## What follows

`spec.md` (user stories, FRs, success criteria including a judged-fixture accuracy criterion), then
`research.md` recording the measured dependency comparison from D2, then `tasks.md`.

The first fixtures to point at it are already written and already disagree with each other by intent:
`benign-tool-001` and `indirect-tool-003`, structurally identical and oppositely labelled.
