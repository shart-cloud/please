# Phase 1 Data Model: the judgement tier

**Feature**: `004-judgement-tier` | **Date**: 2026-08-16

Entities from [spec.md](./spec.md) under the decisions in [plan.md](./plan.md) and [research.md](./research.md).

The shape to hold in mind: **the judge is a `Verdict → Verdict` transformation** (R4). Everything below either
feeds that transformation or is produced by it. Nothing here lives in `please-core`.

---

## Endpoint and credentials

### Credential

The resolved authentication, and the variable it came from.

| Field | Notes |
|---|---|
| `source` | Which variable supplied it — the only part that may ever be displayed |
| `header` | `Authorization: Bearer …` or `x-api-key: …`, decided by `source` |
| *(value)* | **Private, and never rendered.** No `Debug`, no `Display`, no serialisation |

**Invariant (FR-413)**: the value cannot reach a verdict, log, error, or diagnostic. Held as a newtype with a
hand-written `Debug` that prints the source and nothing else — the same technique `Provenance` uses to make a
guarantee structural rather than remembered, and for the same reason: a derived `Debug` on a credential is one
`{:?}` away from a leak, and the `{:?}` will be added by someone debugging at 2am.

### Resolution

The outcome of consulting the environment, computed **without making a request** (FR-414).

| Field | Notes |
|---|---|
| `selected` | The variable chosen, or none |
| `ignored` | Variables that were set and passed over. This is what makes "why is it using that one" answerable |
| `endpoint` | Resolved from `ANTHROPIC_BASE_URL`, defaulting to Anthropic's |
| `model` | Resolved from `ANTHROPIC_MODEL`, defaulting to a pinned id |
| `warnings` | e.g. an API key bound for a non-default host (FR-415) |

Order is unconditional: `ANTHROPIC_AUTH_TOKEN`, `CLAUDE_CODE_OAUTH_TOKEN`, `ANTHROPIC_API_KEY` (plan D3).
`ignored` exists because in practice several are set at once — that is the normal case, not the edge case.

---

## The request

### JudgeRequest

Assembled from a `Verdict` plus the original input. One request per verdict (plan D4).

| Field | Notes |
|---|---|
| `document` | The scanned content, **neutralised** by the existing sanitisation path (FR-408) |
| `spans` | One entry per observation to arbitrate: an opaque id, and the neutralised excerpt |
| `prompt_version` | Recorded in the result (R3) |

**No field says why a span is present.** There is no rule id, no class, no severity, and no "our scanner
flagged this" (FR-406). The span list is *"look at these places"*, not *"we think these are attacks"* — the
schema makes the leading question inexpressible rather than merely discouraged.

**A request is not made at all when `spans` is empty** (FR-404). Nothing to arbitrate.

---

## The response

### Features

What the model returns. Every field is a closed enum; there is no free text anywhere (FR-405). The full JSON
Schema is in [contracts/judge-response.schema.json](./contracts/judge-response.schema.json).

**Document-level**, answered once:

| Field | Options |
|---|---|
| `addressed_to` | `document_recipient` · `processing_agent` · `unclear` |
| `imperative_source` | `document_author` · `quoted_third_party` · `none_present` |
| `framing` | `presented_as_example` · `presented_as_data` · `presented_as_report` · `none` |
| `stated_purpose_explains_content` | `yes` · `no` · `unclear` |

**Per span**:

| Field | Options |
|---|---|
| `span_id` | Echoes a `JudgeRequest.spans` id |
| `span_role` | `instruction` · `description_of_an_instruction` · `unrelated` |
| `span_relation_to_document` | `is_what_the_document_shows` · `incidental_to_what_the_document_shows` · `unclear` |

> **`span_relation_to_document` added by plan D4a, from measurement.** The document-level fields and
> `span_role` answer **identically** for the two discriminating fixtures, and every answer is correct — grep
> output is data, a TODO comment is a description of an instruction. At document scale the two documents
> genuinely are the same, so no combination of correct document-level answers separates them. This field is
> the one that does: `cat payloads.txt` shows its payloads as the subject, `grep -r TODO` carries one as a
> passenger.
>
> It is also the field the tier's accuracy rests on, which makes it the one SC-407's agreement measurement
> most needs to cover.

**Recorded, never read** (FR-410): `model_severity`, an integer. Stored beside the derived score so the
question *"could we have just asked it?"* can eventually be answered from data. Nothing branches on it, and a
test asserts nothing does.

**Validation**: unknown fields rejected, unknown enum values rejected, a `span_id` not in the request
rejected, a missing span rejected. Any failure is `TierUnavailable`, not a partial result (FR-409) — a
response that is *half* trustworthy is not trustworthy, and the salvage path is where a lenient parser on
adversarial input would live.

### `unclear` is a real answer

Present on every field where it makes sense, and cheap to choose. Models over-commit when abstention is not
offered, and this tier is asked precisely about text that is genuinely ambiguous.

**A verdict of `unclear` everywhere demotes nothing.** The structural verdict stands unchanged. Abstention
must never be cheaper for an attacker than honesty (spec Edge Cases).

---

## The outcome

### SpanJudgement

The derived result for one observation. **Two possible values, and that is the security property** (FR-403).

| Value | Effect |
|---|---|
| `Confirmed` | The observation stays reported, annotated as judge-confirmed |
| `Demoted` | The observation moves to `Verdict::suppressed()`, annotated with the judge as what suppressed it |

There is no `Cleared`, no `Escalated`, and no `Added`. Not "we validate against them" — **they are not
representable**, so SC-406's property test is checking a type rather than a code path.

Derived by our code from the answers (FR-407). The function is deliberately trivial and, since plan D4a,
takes **three** conditions rather than two — all required:
`span_role: description_of_an_instruction`, **`span_relation_to_document: is_what_the_document_shows`**, and
one corroborating document-level field. Anything else confirms, including `unclear` on any of them. Tuning
waits for the corpus; the middle condition is not tuning, it is the axis.

### JudgeReport

What the tier adds to a verdict.

| Field | Notes |
|---|---|
| `model` | Resolved model id (R3, FR-416) |
| `prompt_version` | (R3, FR-416) |
| `features` | The document-level answers, as returned |
| `judgements` | Per span: the id, its `span_role`, and the derived `SpanJudgement` |
| `model_severity` | Recorded, unread |

Enough to answer *"why did it do that"* from the verdict alone, which is what US5 asks and what 002
established as the standard when it removed the two-run diff.

---

## Amendments (post-breakdown, from reading the code)

Four things this document asserted turned out to need a decision. Recorded here the way 002 and 003 recorded
theirs, rather than silently corrected.

### A1 — `JudgeReport` lives in `please-core`, not here (plan D10)

This document said "Nothing here lives in `please-core`" and that is now wrong for the **vocabulary**.
`Verdict` is a core type, so an `Option<JudgeReport>` accessor on it must be too, and so must every enum the
report contains. `Features`, `SpanJudgement` and `JudgeReport` are therefore defined in
`please-core::verdict` as plain data with no logic and no dependencies — the same category as
`QuotingContext`.

`Credential`, `Resolution`, `JudgeRequest`, the client, and the scoring function are unaffected and stay in
`please-judge`. **Core may describe a judgement; only `please-judge` may obtain one.**

### A2 — A truncated verdict is not judged (plan D9)

This document claimed "Demotion happens before finalization recomputes, so a demoted observation does not
score." That is true of `finalize`, and **not** true of `rejudge`: the score is aggregated from observations
*before* truncation (001 FR-001b), so a verdict whose reasons were truncated has already lost the severities
it was scored from.

`rejudge` therefore rejects a verdict with `reasons_truncated() == true`, recording
`CoverageGap::failure(TierUnavailable, "verdict truncated before judgement")`. Outcome: `Inconclusive`. This
is a fail-closed path, not a special case — under-scoring a judged verdict would be a fail-open reachable by
arithmetic alone.

`rejudge` reuses finalization's private `assemble` rather than calling `Verdict::new`, so
`tests/seams.rs::exactly_one_place_constructs_a_verdict` continues to assert exactly one construction site,
unmodified.

### A3 — A `span_id` identifies an **observation**, not a region of text

Two rules can fire on overlapping or identical spans, so "one entry per observation" and "one answer per
span" are not the same statement. The request carries one entry per reason in the verdict's `reasons()`
order, and `span_id` is an opaque token minted per entry — not a byte offset, not a rule id, and not stable
across runs.

Consequence worth naming: two entries with identical excerpt text may receive different `span_role` answers.
That is the model being inconsistent, it is visible in the `JudgeReport`, and it is not something to smooth
over in the parser.

### A4 — There is no "confirmed" annotation on a `Reason`

`Confirmed` means *nothing happens to the observation*. It stays in `reasons()`, unchanged, byte-identical to
the structural one. The record that a judge looked at it and confirmed it lives in `JudgeReport.judgements`
and nowhere else.

Adding a `confirmed_by` field to `Reason` was considered and rejected: it would put judge state on the type
whose whole guarantee is that finalization decides its contents, to record an event that changed nothing.

---

## What changes in `please-core`

**Almost nothing, and that is the point of R4.**

`QuotingContext` gains no variant. A judge-demoted observation is not *quoted* — it was demoted by a
judgement, and calling that a quoting context would be the `Encoding` mistake again: a name that stops
describing its members.

So `Reason::suppressed_by` needs a wider type. Two candidates:

| Option | For | Against |
|---|---|---|
| A new `SuppressedBy { Quoting(QuotingContext), Judge }` | honest; the two causes are different kinds of thing | a public type change on the verdict surface, third class-shaped edit in three features |
| A `ConcealingContext`-style sibling list | no change to existing types | a second list to keep consistent — the thing 002 spent Phase 2 removing |

**Recommend the first**, with the amendment recorded the way 002 and 003 recorded theirs. The alternative
trades a visible breaking change for an invisible consistency obligation, and this project has now twice
concluded that is the wrong trade.

`IncompleteCause::TierUnavailable` needs **no change** — it has existed since 001 with no production call site
and this is what it was reserved for.

Beyond `suppressed_by`, core gains the vocabulary in A1 and one function, `finalize::rejudge`. It gains no
dependency, no I/O, and no way to produce a `JudgeReport` of its own.

---

## Flow

```text
  input bytes ──► Engine::scan ──────────────────────────► Verdict        (offline, infallible)
                                                              │
                                        ┌─────────────────────┴── --judge? ──── no ──► unchanged
                                        ▼
                               JudgeRequest  (neutralised document + spans, no rule ids)
                                        │
                                        ▼
                        Anthropic-compatible endpoint, one POST, tool-use schema
                                        │
                     ┌──────────────────┴──────────────────┐
                     ▼                                     ▼
                 Features                        unreachable / unparseable
                     │                                     │
                     ▼                                     ▼
        derived SpanJudgement per span          CoverageGap(TierUnavailable)
                     │                                     │
                     ▼                                     ▼
        confirm, or move to suppressed()          Inconclusive, never Clean
                     │                                     │
                     └──────────────► Verdict ◄────────────┘
```

Two one-way properties, both from plan D5. The judge can move an observation **into** the suppressed channel
and never out of the verdict; and every failure path lands on the right of the diagram, where the outcome is
`Inconclusive`.

## Invariants preserved from earlier features

- A `Clean` outcome still requires no observations and no coverage gaps (001 FR-004). A judge that demotes
  everything produces `Clean` **because the reported set is empty**, not because anything was erased — the
  observations are all in `suppressed()`.
- Score aggregates over observations before truncation (001 FR-001b, 002 FR-124). Demotion happens before
  finalization recomputes, so a demoted observation does not score.
- Excerpts are neutralised at one boundary (001 FR-021, 002 FR-126). The judge receives what a reader
  receives, and adds no new path by which raw content reaches anyone.
- `--no-judge` reproduces the structural verdict byte-identically (FR-418), which keeps 001's SC-011
  determinism guarantee true of the default path.
