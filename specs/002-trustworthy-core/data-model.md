# Phase 1 Data Model: Trustworthy Core

**Feature**: `002-trustworthy-core` | **Date**: 2026-08-15

Entities from [spec.md](./spec.md) under the decisions in [research.md](./research.md). Two module trees own
everything here: **preparation** (rules → executable state) and **finalization** (evidence → verdict).

---

## Preparation

### Provenance

The trust origin of a rule or rule set. A **value**, not an assertion (P1).

| Variant | Meaning | Constructible by |
|---|---|---|
| `Builtin` | Shipped inside the binary; validity established in continuous integration | preparation only |
| `Supplied` | Provided by a caller at run time | anyone |

Represented as a public type wrapping a private discriminant, so reading is public and minting `Builtin` is
not. FR-104's "unforgeable" is enforced by the compiler rather than by review: a caller naming their rule set
`please.builtin` gains nothing, because the name is content and provenance is not derived from content.

### Rule (extended)

Gains one field:

| Field | Notes |
|---|---|
| `provenance` | Set at parse time from the source the rule came from. **Survives resolution** (FR-105), which is what makes delta validation possible — after resolution you must still be able to tell which half is untrusted |

### ValidationRecord

Evidence that resource validation succeeded, and what it succeeded *against*. A **state**, not a discarded
check result — which is the thing currently missing (loss #2).

| Field | Notes |
|---|---|
| `limits` | The limits validation was performed against |
| `covered` | Which rules were validated. Built-in rules under a default-limit record are covered by the CI check rather than by a run-time pass |

**Staleness rule (FR-108)**: a record is only usable for constructing an executable capability whose limits are
**no stricter** than `limits`. Tightening forces revalidation. Without this, "validated" is meaningless — you
could validate at generous limits and run at severe ones.

### PreparedRuleset

The only thing an executable scanning capability can be built from (P2).

| Field | Notes |
|---|---|
| `id` | Name, version, and a digest covering content **and** provenance and validation state (FR-111) |
| `rules` | The resolved set, each carrying its provenance |
| `bands` | Score-to-risk table |
| `record` | The validation record above |
| `warnings` | Non-fatal load observations |

**Invariant (FR-102, FR-103)**: every constructor validates. There is no path to a `PreparedRuleset` that
skips validation, so "the caller forgot" is not expressible rather than being documented against. The public
`validate_compiled` operation is **removed** — while it exists as a separate call, some caller will omit it,
which is the current situation exactly.

**What validation covers (FR-107)**: every rule present, including rules marked `enabled = false`. Skipping
disabled rules would let flipping `enabled` in a file turn a validated set into an unvalidated one with no
construction occurring — validation state would go stale silently.

**What it does not cover (FR-110)**: suppression. Removing rules cannot introduce a resource problem.
Suppressing an unknown identifier remains an error, which is cheap and unrelated.

### Validation scope by operation

| Operation | Compiled validation | Why |
|---|---|---|
| Built-in base | No, at default limits | Established in CI (FR-106) |
| Built-in base, tightened limits | **Yes** | The CI record no longer applies (FR-108) |
| Caller addition | Yes — **the added rules only** | The built-in half is already known good; delta validation is what keeps cost proportional to caller rules (SC-105) |
| Caller replacement of a built-in | Yes, the replacing rule | It is caller-supplied. The displaced rule leaves the set |
| Suppression | No | Cannot create a resource problem |
| Disabled rule | Yes | `enabled` is flippable data (FR-107) |

### Matcher

Owns the rule slice, the literal prefilter, and the compiled-pattern store — and therefore owns the **position
space privately** (P4, FR-140).

Its interface yields observations carrying a rule *reference*. No positional identifier crosses a seam, so
there is nothing for three components to disagree about. Compiled slots are pre-filled by validation for
caller-supplied rules and left empty for built-in ones, so no pattern is compiled twice (FR-109).

---

## Finalization

The verdict types live **inside** this module tree, with constructors visible only to it. Not a stylistic
choice: the alternative does not compile (P3). They are re-exported so embedders name them unchanged.

### Observation

What a detector saw. A detector's **only** output (FR-121).

| Field | Notes |
|---|---|
| `rule_id` | Stable identity, never a position |
| `class` | **One** class, decided by whatever emitted the observation |
| `span` | Location in the original input |
| `matched` | Raw content; neutralised on the way into a reason, not here |
| `severity` | |
| `chain` | Transformations by which it arrived — empty for a direct match |

**One class, decided once (FR-133)**: the current defect is that a decoded observation is gated on its rule's
class and then labelled with another, so it must pass two filters. An observation carries exactly one class and
the filter is applied exactly once, in the plan.

### CoverageGap

Something the scan did not examine, recorded in one vocabulary at the point it occurred, by the code that knows
why (FR-122).

Causes divide as before into **bounds** (carrying the configured value; a caller can raise them) and
**failures** (a caller may be able to fix the environment). What changes is *who records them*: the detector
that hit the bound, rather than a caller translating a boolean.

The judgement of what constitutes a gap leaves the decoder entirely (FR-123). It is a policy question, and
putting it in a decoder is how "every scan returns inconclusive" happened in 001 — unconditional transforms
always had more to do, so the decoder's notion of "more remaining" was never the same as "coverage was
incomplete".

### Suppression

A retained observation that quoting suppressed, with the context that suppressed it (FR-128).

| Field | Notes |
|---|---|
| `observation` | The full observation, not a summary |
| `context` | Which quoting context suppressed it |

Retained rather than discarded because suppression is the principal lever on the open false-positive problem
and its effect is currently unmeasurable in a single run. This turns "what did suppression change?" from a
two-run experiment into a field.

### Evidence

The accumulated observations, coverage gaps, and suppressions of one scan.

**Write-only to detectors, read-only to finalization** (P6). Detectors receive a handle exposing only record
operations; they cannot read the accumulator, so they cannot maintain a parallel view of it. That is what makes
FR-124 structural: with one collection and no way to shadow it, score-over-all-observations is the only thing
expressible, and the two-collections-must-agree bug class disappears rather than the instance.

### ScanPlan

What this scan will examine, derived once from policy and the prepared rule set (FR-129).

| Field | Notes |
|---|---|
| `classes` | Active detection classes, **resolved once** |
| `rules` | Participating rules after the class filter |
| `bounds` | Input size, decode depth, match and reason caps, excerpt length |
| `suppress_in_quotes` | Whether the quoting pre-pass suppresses |

Read-only to every stage. The single resolution of `classes` is the fix for the double-gate: one application
site cannot disagree with itself.

### DetectionClass (amended)

Five variants. `Encoding` is **removed** (FR-131).

| Class | Detects |
|---|---|
| `Override` | Instructions to disregard prior instructions |
| `Concealment` | Text hidden by invisible or direction-altering characters |
| `Confusable` | Characters imitating other characters |
| `Boundary` | Forged role markers, tool-result impersonation, delimiter breakout |
| `Solicitation` | Requests for the agent's instructions or credentials |

A class names a **kind of finding**, never a delivery mechanism (FR-130). A payload recovered by decoding
carries the class its rule declares; the decoding is in `chain` (FR-132). Disabling decoding remains the depth
bound (FR-135), which is what it always was.

The removed class had no members: no rule could declare it, and it was applied only by the decode path to
observations from `override`, `boundary`, and `solicitation` rules. It named a mechanism while the design
states an encoding is never itself a finding — the contradiction that produced the defect.

---

## Flow

```text
                    ┌──────────────── preparation ────────────────┐
  rule sources ────►│ parse → resolve → identify → validate →      │
  (embedded,        │ retain compiled state                        │
   caller files)    └──────────────┬──────────────────────────────┘
                                   │ PreparedRuleset  (the only way through)
                                   ▼
                     ScanPlan ──────────────┐  read-only
                         │                  │
                         ▼                  ▼
  input bytes ────► detectors & decoders ──────► Evidence      write-only
                                                    │
                                                    ▼
                                          ┌── finalization ───┐
                                          │ score → band →    │
                                          │ order → truncate  │
                                          │ → outcome         │
                                          └────────┬──────────┘
                                                   ▼
                                                Verdict
```

Two one-way seams. `PreparedRuleset` is the only path from rules to an executable capability; `Evidence` is the
only path from observations to a verdict. Neither can be gone around, and both are enforced by visibility
rather than by documentation.

## Invariants preserved from 001

Unchanged in meaning, now unreachable by any other route:

- A `Clean` outcome requires no observations **and** no coverage gaps (001 FR-004).
- `RiskFound` outranks `Inconclusive` outranks `Clean` (001 FR-032b).
- Score aggregates over all observations before truncation (001 FR-001a/b) — now structurally rather than by
  discipline.
- Excerpts are neutralised on the way into a reason (001 FR-021) — now at the only site that builds one.
