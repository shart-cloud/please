# Phase 1 Data Model: Structural Detection & Scan CLI

**Feature**: `001-structural-detection-cli` | **Date**: 2026-08-15

Entities from [spec.md](./spec.md), given concrete shape under the decisions in
[research.md](./research.md). Field types are described in language-neutral terms; the serialised
form is fixed by [`contracts/verdict.schema.json`](./contracts/verdict.schema.json).

---

## Outcome

The three-way result required by FR-003. Mutually exclusive, and the root of the whole model —
everything else hangs off which of these three a scan produced.

| Variant | Meaning | Produced when |
|---|---|---|
| `clean` | Analysis completed; nothing found | No rule fired **and** nothing was left unexamined |
| `risk_found` | Analysis found at least one reason | One or more rules fired |
| `inconclusive` | Analysis did not complete | A bound was hit, a target was unreadable, a decoder failed, a rule set was unavailable, or a tier was unavailable |

**Invariant (FR-004, SC-007)**: `clean` requires `reasons` empty **and** `incomplete` empty. A scan
that left anything unexamined is `inconclusive` even when no rule fired. This is the single invariant
the whole fail-closed posture rests on, and it is asserted as a property, not just a unit test.

Keeping it to **two** accumulators is deliberate: a third would be a third place to forget, in the one
check everything else depends on.

**Precedence (FR-032b)**: `risk_found` outranks `inconclusive`, which outranks `clean`. A scan that
found a real payload *and* left something unexamined reports `risk_found`, carrying its `incomplete`
entries so the caller knows the finding may not be the only one. Reporting `inconclusive` there would
discard a confirmed detection. The same precedence derives a directory's summary status from its
per-target verdicts, which is what stops a tree containing one unreadable file from summarising as
clean.

---

## Verdict

The complete result of one scan. Serialised form is the caller-facing contract.

| Field | Type | Notes |
|---|---|---|
| `outcome` | Outcome | Above |
| `score` | integer `0..=100` | Integer by D9; `0` when `clean` |
| `risk` | RiskLevel | Banded from `score`; the human-facing summary |
| `reasons` | ordered list of Reason | Sorted by `(offset, rule_id)`; capped by `max_reasons` |
| `reasons_truncated` | boolean | True when the cap dropped reasons (FR-007) |
| `incomplete` | ordered list of Incompleteness | Empty iff the whole input was examined |
| `target` | TargetRef | What was scanned; reporting metadata only |
| `ruleset` | RulesetId | Identity and version (FR-005) |
| `engine` | EngineId | Name and version (FR-005) |

**Determinism (FR-030, SC-011)**: no field derives from wall-clock time, hash iteration order, or
absolute paths the caller did not supply. There is deliberately **no timestamp field** — a timestamp
would make byte-identical repeat output impossible, and the caller already knows when it ran the
scan.

### Score aggregation (FR-001a, FR-001b)

```text
score = min(100, max_severity + bonus)
bonus = min(15, 5 × (count of distinct classes present − 1))
```

Three properties this is chosen for, each corresponding to a way the obvious alternatives fail:

- **Insensitive to input length.** A summed score rises as a document grows, so a long benign file
  eventually crosses any threshold. Here a 50-page document and a one-line snippet with the same worst
  finding and the same class mix score identically.
- **Insensitive to match count.** Twenty matches of one rule score exactly as one match of it. Only
  *distinct classes* add, and there are at most six, so the bonus is bounded by construction rather
  than by a cap that has to be tuned.
- **Rewards corroboration.** An override phrase plus concealment plus an encoded payload is genuinely
  more suspicious than any alone, and this is the term that says so.

**Computed before truncation.** Aggregation runs over every match found, not over the reasons that
survive `max_reasons`. Reasons are ordered by byte offset for reproducibility (D9), not by severity, so
truncating first could drop the highest-severity finding and understate the score.

### RiskLevel

`none` | `low` | `medium` | `high` | `critical`, banded from `score` by a documented table. Bands are
data, not code, so a deployment can retune them without a rebuild.

The score exists to be calibrated against the corpus once the evaluation harness lands; until then
band boundaries are provisional, and both the plan and the tool's own documentation say so rather than
implying a calibration that has not happened. SC-003 is measured at the default threshold, so the
fixture-era band values are recorded alongside the metric — a later recalibration should read as a
visible diff, not as a number that quietly moved.

---

## Reason

One supporting observation (FR-002). The unit that makes a finding actionable — a verdict without
these is an assertion, not evidence.

| Field | Type | Notes |
|---|---|---|
| `rule_id` | stable identifier | Namespaced, e.g. `override.ignore_previous` |
| `class` | DetectionClass | Below |
| `span` | Span | Location in the **original** input |
| `matched` | sanitised excerpt | Neutralised per FR-021; length-capped |
| `severity` | integer `0..=100` | This rule's contribution before aggregation |
| `chain` | ordered list of Transform | Empty for a direct match; populated when found via decoding |
| `suppressed_by` | optional QuotingContext | Present only on reasons reported *because* suppression was disabled |

> **Amended by feature 004 (T009).** `suppressed_by` is now an optional **`SuppressedBy`**, not an optional
> `QuotingContext`. The new type is `Quoting(QuotingContext) | Judge`, and the extra variant records that the
> judgement tier moved an observation into the suppressed channel.
>
> **Not a new `QuotingContext` variant**, deliberately. A quoting context is a claim about the *document* —
> this text sits inside a fence, a quote, an example. A judgement is a claim about an *external process*, is
> non-deterministic, is attributable to a model id and prompt version, and is reversible with `--no-judge`.
> Filing the second under the first would be the `Encoding` mistake again: a name that quietly stops
> describing its members. `SuppressedBy::quoting()` exists for callers that only care about the structural
> case, so the widening costs a match arm only where the distinction matters.
>
> Also amended: `Verdict` gains an optional `judge` field carrying a `JudgeReport` (004 FR-416, plan D10).
> Its **absence** is the machine-readable form of "this verdict is purely structural, and SC-011 applies to
> it unchanged".
>
> One pre-existing gap noticed while making this edit and **not** fixed here, because it belongs to 002 and
> silently repairing another feature's contract is how a schema stops being reviewable: the top level of
> `contracts/verdict.schema.json` still lacks `suppressed` and `suppressions_truncated`, which 002 added to
> the `Verdict` type. With `additionalProperties: false` that makes the schema stricter than the type it
> describes. Worth a 002 amendment of its own.
>
> **Closed at 001 T065.** Both fields are now in the schema and in `required`, because a `Verdict` always
> carries them. Two other gaps of the same kind were found at the same time and closed with it: `relation`
> was missing from `judge_report.judgements` — 004's plan D4a added `SpanVerdict.relation` and amended the
> prose contract and this document but not the schema — and `model_severity` is confirmed as deliberately
> absent, since FR-410 gives it no accessor and the serialiser skips it.
>
> **All three were invisible for the same reason: nothing had ever validated output against this file.**
> The schema was maintained across four features as a document. 001 T065 makes it a contract, and the first
> thing a contract does is find where it drifted.

**Span in original coordinates**: when a match is found in decoded content, `span` still points into
the original input — at the encoded region that produced it. A caller highlighting a finding must be
able to show the user the bytes they actually have. The decoded position is carried inside `chain`.

**`matched` is never raw**: it passes through neutralisation before it enters a Verdict, so FR-021
holds for every consumer, including ones that forget. Sanitising at the boundary rather than at each
display site is the same ordering discipline bee's `safe_text` documents — sanitise the payload,
then style it, never the reverse.

---

## DetectionClass

Named families, independently reportable and disableable (FR-015). A class names the **kind** of finding,
never how it was delivered. The set is closed for this slice; adding a class is a spec change, because each
one carries an accuracy criterion.

| Class | Detects | Requirement |
|---|---|---|
| `override` | Instructions to disregard, replace, or supersede prior instructions | FR-008 |
| `concealment` | Text hidden by invisible, zero-width, bidi, tag-block, or variation-selector characters | FR-009 |
| `confusable` | Characters chosen to resemble others, evaluated per token | FR-010 |
| `boundary` | Forged role markers, system-instruction or tool-result impersonation, delimiter breakout | FR-012 |
| `solicitation` | Requests for an agent's instructions, configuration, or credentials | FR-013 |
| `agent_directed` | Content addressing the reading agent rather than the document's human recipient | 003 FR-301 |

> **Amended by feature 002 (FR-130, FR-131, T054).** A sixth class, `encoding` — "payloads recovered by
> bounded decoding", FR-011 — has been **removed**.
>
> It was the only class that named a *delivery mechanism* rather than a kind of finding, and that
> contradicted D5's rule, stated three sections below, that an encoding is never itself a finding. It also
> had no members: no rule could declare it, and it was applied only by the decode path, to observations
> produced by `override`, `boundary`, and `solicitation` rules.
>
> The consequence was a shipped defect. A decoded observation was gated on its *rule's* class, then
> relabelled `encoding`, then gated again on *that* class — so it had to satisfy two different filters and no
> single `--classes` selection satisfied both. `--classes override` reported a base-64 override payload as
> clean; `--classes encoding` matched nothing at all. FR-015's promise of independent addressability did not
> hold.
>
> A payload recovered by decoding now carries the class its rule declares, and FR-011's subject matter lives
> where it always belonged: in the finding's `chain`. Disabling decoding is `max_decode_depth`, which is what
> it always was.

> **Amended by feature 003 (FR-301).** A sixth class, `agent_directed`, has been **added**.
>
> It passes the test `encoding` failed: it names a kind of finding rather than a delivery mechanism, and rules
> can declare it. It is distinct from `boundary` in the way that matters — forging is a claim about **who is
> speaking**, addressing is a claim about **who is listening**. A forged `SYSTEM:` marker claims the
> platform's authority; `NOTE TO AI ASSISTANT:` claims nothing, and simply assumes the reader is a machine.
>
> The semantic: in indirect injection the agent is meant to be *processing* content, so content that addresses
> it is anomalous by construction — nothing in the legitimate workflow has a reason to talk to it.

---

## Transform

One link in a decoding chain (FR-011, D5).

| Field | Type | Notes |
|---|---|---|
| `kind` | `base64` \| `hex` \| `rot13` \| `reversed` \| `leetspeak` \| `unicode_tags` \| `variation_selectors` | The five corpus-labelled families plus the two concealment channels that decode |
| `depth` | integer `1..=max_decode_depth` | |
| `input_span` | Span | Region in the layer above that was decoded |
| `decoded_excerpt` | sanitised excerpt | The recovered content that triggered the rule |

A Transform never appears alone. It exists only inside a Reason whose rule fired on decoded
content — the structural encoding of D5's rule that an encoding is not itself a finding.

Since feature 002 this is also the **only** place a delivery mechanism is recorded, the `encoding` detection
class having been removed for contradicting the same rule this paragraph states.

---

## Incompleteness

Something the scan did not examine (FR-003, FR-007, FR-017, FR-018, FR-032a, and the constitution's
no-silent-truncation constraint). Formerly `LimitHit`; widened because an unreadable target is not a
bound anyone configured, and it needed somewhere machine-readable to live.

| Field | Type | Notes |
|---|---|---|
| `cause` | see below | Discriminates a configured bound from an outright failure |
| `configured` | optional integer | Present for bounds, absent for failures |
| `detail` | optional text | Which rule saturated, which region went unexamined, why a target could not be read |

**Bounds** — a limit the caller set, and can raise:

| Cause | Requirement |
|---|---|
| `input_size` | FR-017 |
| `decode_depth` | FR-018 |
| `max_matches_per_rule` | D2, FR-007 |
| `max_reasons` | FR-007 |
| `excerpt_length` | FR-021 |

**Failures** — something the environment did, and the caller may be able to fix:

| Cause | Requirement |
|---|---|
| `target_unreadable` | FR-032a |
| `decode_failed` | FR-003 |
| `ruleset_unavailable` | FR-024 |
| `tier_unavailable` | Constitution Principle I — an unavailable optional tier degrades to inconclusive, never to clean |

The split is what a caller *does about it*: raise a limit, or fix an environment. It is expressed in
the enum and in whether `configured` is present, rather than in two separate lists, so the FR-004
invariant stays a check on one field.

Any `Incompleteness` forces `inconclusive` unless a reason was also found. An unexamined region that
goes unreported is the failure mode this entity exists to prevent — it is the fail-open that FR-004
forbids, arriving through the side door.

---

## Rule

One declarative detection definition (FR-022). Authored as TOML; the reviewable artifact.

| Field | Type | Notes |
|---|---|---|
| `id` | stable identifier | Namespaced; the handle for suppression (FR-023) |
| `class` | DetectionClass | |
| `severity` | integer `0..=100` | Contribution to the aggregate score |
| `literals` | list of required literals | Feeds the prefilter (D4); a rule with none is always-evaluated and must justify itself |
| `pattern` | pattern source | Compiled lazily; no lookaround or backreferences are expressible (D1) |
| `fires_in_quotes` | boolean, default false | Whether the rule survives the quoting pre-pass (D8) |
| `enabled` | boolean, default true | |
| `description` | text | Why this rule exists; shown in output so a finding explains itself |

**Load-time validation (FR-024, D3)**: a rule is rejected — failing the whole set — if its pattern
exceeds the source-length limit, its compiled size exceeds the program-size limit, its `id` collides
or is malformed, or its `class` is unknown. Partial loading is never permitted: a half-loaded rule
set is indistinguishable from a weakened one.

---

## Ruleset

A versioned, identified collection of rules (FR-005, FR-023, FR-025).

| Field | Type | Notes |
|---|---|---|
| `id` | RulesetId | Name plus version, recorded in every Verdict |
| `rules` | ordered list of Rule | Deterministic order for reproducibility |
| `bands` | score-to-RiskLevel table | Data, per RiskLevel above |

**Resolution order**: built-in default → caller-supplied additions → caller-supplied suppressions.
Suppression is by rule `id`. The resolved set's identity is derived from the identities and content
of its inputs, so two callers reporting the same `RulesetId` really did run the same rules — which is
what makes SC-012 (attributing an old verdict to exact rules) hold.

The built-in set is embedded in the binary, so a first run needs no filesystem and no network
(FR-025, FR-031) — which is also what lets the same set work in a browser.

---

## ScanPolicy

Caller-owned configuration (FR-006). Never derived from scanned content (FR-020).

| Field | Type | Default | Requirement |
|---|---|---|---|
| `max_input_bytes` | integer | 1 MiB | FR-017 |
| `max_decode_depth` | integer | 3 | FR-018 |
| `max_matches_per_rule` | integer | 16 | D2, FR-007 |
| `max_reasons` | integer | 64 | FR-007 |
| `max_excerpt_bytes` | integer | 256 | FR-021 |
| `threshold` | RiskLevel | `high` | FR-029 |
| `classes` | set of DetectionClass | all | FR-015 |
| `suppress_in_quotes` | boolean | true | D8 |

Defaults are provisional pending calibration and are documented as such. `max_input_bytes` at 1 MiB
sits an order of magnitude above the corpus maximum of 82,300 bytes while staying far below anything
that threatens the linear-time budget.

---

## TargetRef

What was scanned — reporting metadata only, and explicitly never an input to judgement (FR-020),
so that a file's name or path can never influence its own verdict.

| Field | Type | Notes |
|---|---|---|
| `kind` | `path` \| `stdin` \| `buffer` | |
| `name` | optional text | Caller-supplied label or the path as given, never absolutised (D9) |
| `bytes` | integer | Size as read |

---

## Relationships

```text
Verdict ──1:1── Outcome
   │
   ├──0..N── Reason ──1:1── DetectionClass
   │            │
   │            ├──0..N── Transform        (populated only for decoded matches)
   │            └──0..1── QuotingContext
   │
   ├──0..N── Incompleteness
   ├──1:1─── TargetRef
   ├──1:1─── RulesetId ◄── Ruleset ──1..N── Rule ──1:1── DetectionClass
   └──1:1─── EngineId

ScanPolicy ──governs──► the scan that produces a Verdict
```

## State transitions

A scan is a straight-line pipeline; there is no persistent state and no state machine to get wrong.
Each stage can only add reasons or record limits, never remove them:

```text
read → size gate → normalise/decode (bounded, cycle-guarded) → structural pre-pass
     → literal prefilter → lazy pattern evaluation → quoting suppression
     → aggregate score → band → assemble Verdict
```

The size gate can short-circuit to `inconclusive`. Every other stage runs to completion or records a
an Incompleteness. Monotonic accumulation is what makes the FR-004 invariant checkable at a single point: at
assembly, `clean` is chosen only if both accumulators are empty.
