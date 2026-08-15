# Contract: verdict finalization

**Feature**: `002-trustworthy-core`

The seam between what detectors saw and what the tool says. One sentence: **only finalization can produce a
verdict, and detectors can only produce observations.**

Both halves are enforced by visibility, not by convention.

---

## Three roles, one direction

| Role | Reads | Writes |
|---|---|---|
| `ScanPlan` | every stage | nobody — derived once, then immutable |
| `Evidence` | finalization only | detectors and orchestration |
| `Verdict` | everybody | finalization only |

`Evidence` being **write-only to detectors** is the load-bearing asymmetry. A detector that cannot read the
accumulator cannot keep a parallel view of it, so score-over-all-observations is the only thing expressible.
That is how "aggregate before truncate" stops being a discipline two collections must maintain and becomes the
only available behaviour.

## What detectors may say

Exactly two things:

**An observation** — rule identity, one class, a span in the original input, matched content, severity, and the
transformation chain by which it arrived. Raw content: neutralisation happens on the way into a reason, at the
single site that builds one, so it cannot be forgotten by a consumer.

**A coverage gap** — recorded at the point it occurred, by the code that knows why, in one shared vocabulary.
A bound carries the configured value that stopped analysis; a failure carries what went wrong.

What a detector **cannot** do, as a compile error rather than a review note: construct a reported reason,
construct a coverage-gap record directly, or construct a verdict. `error[E0624]: associated function 'new' is
private`.

## What finalization owns

Everything between evidence and a verdict, and nothing else:

- The **only** constructor for a verdict
- Score aggregation over all observations, **then** truncation of what is reported
- The single definition of reason ordering
- Outcome precedence and the clean invariant
- Banding score to risk level
- Observation → reason, including excerpt neutralisation and any gap that truncation produces
- Whether suppressed observations are reported

## What it does not own

The judgement of what constitutes a coverage gap does not live in a decoder or a matcher (FR-123). This is
where 001 went wrong: a decoder decided "there is more to decode" and that was treated as "coverage was
incomplete". Those are different propositions — unconditional transforms always have more to do — and conflating
them made every scan inconclusive.

A decoder reports *what it did not examine*. Whether that makes a verdict inconclusive is a verdict question.

## One class, one filter

An observation carries exactly one detection class, decided by whatever emitted it. The active-class filter is
applied exactly once, in the plan.

The defect this replaces: a decoded observation was gated on its rule's class and then labelled with a
different one, so it had to survive two filters. Neither `--classes override` nor `--classes encoding` alone
could find a base-64 override that the default policy detected. With one class and one filter, selecting a
class finds every finding of that class regardless of how it arrived.

Delivery lives in the chain. `Encoding` is not a class, because it named a mechanism.

## Suppression is evidence

A suppressed observation is retained with the context that suppressed it, and finalization decides whether to
report it.

This exists because suppression is the principal lever on the open security-prose false positives, and its
effect is currently unmeasurable in a single run: the suppressed observations are computed and dropped, and
`suppressed_by` on a reason can only ever be absent. Answering "what did suppression change here?" requires two
runs and a diff. It should be a field.

## Preserved from 001, now unreachable by any other route

| Guarantee | Status |
|---|---|
| `Clean` requires no observations **and** no coverage gaps | unchanged in meaning; one enforcement site |
| `RiskFound` > `Inconclusive` > `Clean` | unchanged |
| Score reflects every observation, not the truncated report | unchanged; now structural |
| Excerpts neutralised before a consumer sees them | unchanged; now at the only construction site |
| Byte-identical output for identical input and rules | unchanged; one ordering definition instead of two |

## Public reading path

The verdict types move inside finalization but stay named where embedders already name them, via re-export.
An embedder reading `Verdict`, `Reason`, `Outcome`, or `Incompleteness` sees no change; only the ability to
*construct* them moves — and it moves from "everywhere in the crate" to "one module".
