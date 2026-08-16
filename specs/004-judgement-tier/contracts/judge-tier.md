# Contract: the judgement tier

**Feature**: `004-judgement-tier`

Three surfaces: what an operator invokes, what goes on the wire, and what an embedder calls. The response
schema is [judge-response.schema.json](./judge-response.schema.json).

---

## CLI surface

```sh
plz scan --judge <target>              # opt-in, per invocation
plz scan --no-judge <target>           # explicit off; also the default
plz scan --judge --judge-timeout 5      # whole seconds
plz judge --check                      # resolve credentials and endpoint; make NO request
```

`--judge` is unavailable unless the binary was built with `--features judge`. On a default build it is an
**unknown flag**, exit `64` — not a silently ignored one. A security tool that accepts a flag it cannot honour
is worse than one that refuses it. **The whole `judge` subcommand is absent on a default build too**, by the
same argument.

Two mechanics worth pinning here rather than leaving to the implementation:

- `--judge` and `--no-judge` are **last-flag-wins**, which needs `overrides_with` rather than two independent
  booleans. `plz scan --judge --no-judge` is a structural scan, and the ordering is the point: a wrapper
  script appending `--no-judge` must be able to override a config that supplied `--judge`.
- `--judge-timeout` takes **whole seconds as an integer**, not `5s`. A duration parser would be a new crate
  in the CLI's *default* dependency graph, for a flag the default build does not have — which is precisely
  the leak FR-419's gate exists to catch.

### `plz judge --check`

Answers *"what would you do"* without doing it (FR-414). Makes no network request, so it is safe to run
anywhere and cannot leak a credential to an endpoint by testing it.

```text
$ plz judge --check
  endpoint   https://proxy.internal.example/v1     (ANTHROPIC_BASE_URL)
  model      claude-sonnet-4-5                     (default; ANTHROPIC_MODEL unset)
  credential ANTHROPIC_AUTH_TOKEN  →  Authorization: Bearer
  ignored    ANTHROPIC_API_KEY     (set; lower precedence)
             CLAUDE_CODE_OAUTH_TOKEN (unset)
```

**No line of that output contains a credential value**, and a test asserts it over the whole suite (SC-404).
The `ignored` column exists because several variables are commonly set at once — that is the normal case, and
"why is it using that one" should not require reading this document.

### Exit codes

Unchanged from `contracts/cli.md`. The judge introduces **no new code**, and that is deliberate: a judged scan
and an unjudged one are the same three outcomes, so a hook branching on status needs no change to keep
working.

| Situation | Code | Why |
|---|---|---|
| Judge demoted everything, nothing reported | `0` | Clean. The suppressed list carries the story |
| Judge confirmed a finding at or above threshold | `1` | Risk found |
| Judge confirmed a finding below the threshold | `3` | Risk found, under the caller's bar |
| **Judge unavailable, for any reason** | `1` or `3` | **Never `0`** (FR-402). The findings stay reported and a `TierUnavailable` gap names the cause |
| Nothing to arbitrate, judge never asked | `0` | FR-404. No observations, no request, no gap |
| `--judge` (or `judge`) on a build without the feature | `64` | Usage |

> **Amended during implementation (T030).** The unavailable row said `2`, and `2` turns out to be
> **unreachable through this tier**. Two requirements combine to make it so:
>
> - FR-404 skips the request entirely when a verdict has no observations, so every verdict the judge *can*
>   fail on has at least one reason;
> - `RiskFound` outranks `Inconclusive` in the outcome precedence (001 FR-032b), because a scan that found a
>   real payload and then lost its second opinion has still found a real payload.
>
> So a failed judgement always lands on `1` or `3`, carrying a `TierUnavailable` gap in a verdict that is
> visibly not clean. **The guarantee was always "never `0`"** — `2` was one way of achieving it, and the
> precedence rule achieves it more strongly, since `1` tells a caller there is something to look at and `2`
> only tells them the tool is unsure.
>
> `plz scan --judge` still emits `2` by the ordinary route: an unreadable file in a directory walk, an
> oversized input, any pre-existing gap on a verdict with no findings. Nothing about the exit-code contract
> changed; what changed is which row the judge's own failures land in.

The unavailable row is the whole fail-closed posture. An unreachable endpoint, a missing credential, a
timeout, a 401, a proxy without tool-use support, a response that does not validate, a document over the
judgement size limit, **and a verdict whose reasons were truncated before judgement** (plan D9) — all one
behaviour, and it is not "fine".

---

## Wire contract

One `POST` to `{endpoint}/v1/messages`, synchronous, with a timeout (R1, plan D2).

### Headers

| Header | Value |
|---|---|
| `authorization` **or** `x-api-key` | Chosen by which variable supplied the credential (plan D3) |
| `anthropic-version` | Pinned |
| `content-type` | `application/json` |

### Request shape

The model is required to call **one tool** whose input schema is
[judge-response.schema.json](./judge-response.schema.json), which is how a closed-enum answer is obtained
rather than requested in prose (R2).

The content is enveloped as data under analysis. Three rules govern what may appear in it:

1. **Neutralised** by the existing sanitisation path before it leaves the process (FR-408). The judge sees
   what a reader sees; this tier adds no path by which raw content reaches anyone.
2. **No rule identity, class, or severity** accompanies a span. The request says *look at these places*, not
   *we think these are attacks* (FR-406).
3. **None of the words** *injection*, *attack*, *malicious*, *suspicious*, or *risk* appears anywhere in the
   prompt. Naming the interesting answer produces it.

A proxy that rejects tool use is **`TierUnavailable`**, not a fallback to prose parsing. Falling back would
quietly move the conformance boundary from the schema into our parser, which is where a lenient parser on
adversarial input would live.

### Response handling

Validate against the schema, entire. Reject on: unknown field, unknown enum value, unrecognised `span_id`,
missing span, malformed JSON, tool not called. **Every rejection is `TierUnavailable`** — there is no partial
acceptance, because a response that is half trustworthy is not trustworthy.

---

## Library surface

```rust
// please-judge — depends on please-core; core never depends on this.
Resolution::from_env() -> Resolution                    // no request; drives `--check`
Judge::new(Resolution) -> Result<Judge, JudgeError>

// The whole tier, as one transformation. Infallible by the same reasoning as `Engine::scan`:
// every failure mode is a coverage gap in the returned verdict, not an `Err` for a caller to
// unwrap_or_default() into something cheerful.
Judge::review(&self, verdict: Verdict, input: &[u8]) -> Verdict
```

The seam underneath it is in core, because only finalization may produce a `Verdict` (002 FR-120):

```rust
// please-core — the judge supplies decisions; it does not assemble verdicts.
finalize::rejudge(verdict: Verdict, report: JudgeReport) -> Verdict
```

`rejudge` refuses a verdict whose reasons were truncated, recording `TierUnavailable` instead of judging it
(plan D9). It reuses finalization's private `assemble`, so `Verdict::new` keeps its single call site and
`tests/seams.rs` passes unmodified.

### `review` is `Verdict → Verdict`, and can only narrow

Two guarantees, both structural rather than validated (FR-403, data-model `SpanJudgement`):

- **No observation leaves the verdict.** A demoted one moves from `reasons()` to `suppressed()`, annotated
  with the judge as what suppressed it. It is still readable, still explains itself.
- **Nothing is added and nothing is escalated.** `SpanJudgement` has two variants and neither is `Cleared`,
  `Escalated`, or `Added` — so SC-406's property test checks a type, not a code path.

Therefore: for any response whatsoever, including a maximally hostile one,

```text
judged.reasons() ∪ judged.suppressed()  ==  structural.reasons() ∪ structural.suppressed()
max severity in judged                  ≤   max severity in structural
```

### What a caller must still decide

`review` reports; the caller enforces (Principle I). A judge-suppressed finding is *reported as suppressed*,
and whether that blocks is the deployment's policy — exactly as a quoting-suppressed finding already is.

The honest limit, stated where an integrator will read it: **a fully captured judge and a correct judgement of
a benign document produce the same verdict.** They differ only under `--no-judge`, which reproduces the
structural verdict byte-identically (FR-418). That is one command, and it is the whole reason the structural
verdict is preserved rather than replaced.
