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

Derived by our code from `Features` (FR-407). The function is deliberately trivial in the first
implementation: `span_role: description_of_an_instruction`, corroborated by a document-level field, demotes;
anything else confirms. Tuning waits for the corpus.

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
