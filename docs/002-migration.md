# 002 migration order

Task T006. Why this feature lands in this sequence, and what would go wrong in the obvious ones.

The short version: **capture the baseline, build the structure, fix the two defects one commit each,
then complete the refactors, and seal last.** Research P7 sets out nine steps; `tasks.md` groups them
into eight phases. The two documents agree, and where the ordering appears to differ there is a
reason, recorded under "Reconciliation" below.

## The order

| Phase | Research step | What lands | Behaviour |
|---|---|---|---|
| 1 | — | Baselines: accuracy, test inventory, dependency set. Compile-fail harness. Module skeletons | preserving |
| 2 | 1, 2, 3 | `finalize` with the verdict types inside it; all three construction sites routed through it; `Evidence`; `ScanPlan`; gaps recorded at the point they occur | preserving |
| 3 | 4 | **Preparation enforces compiled validation on caller-supplied rules** | **changes** |
| 4 | 5 | **The `Encoding` class is removed; one class filter, in the plan** | **changes** |
| 5 | 7, 8, 9 (verdict half) | Parallel hit collection deleted; duplicate ordering deleted; verdict constructors sealed | preserving |
| 6 | — | Suppression retained and reportable | preserving¹ |
| 7 | 6 | `prefilter` and `patterns` merge into `matcher`; the index space becomes private | preserving |
| 8 | — | Amendments to 001's specs, and the verification tasks | preserving |

¹ Phase 6 adds information to a verdict that was previously discarded (`suppressed_by` is currently
always absent). No finding changes, no score changes, no exit code changes — but the JSON output gains
populated fields, which is a compatible addition rather than a no-op. Worth naming so T084's
comparison is not surprised by it.

## Why the baselines come first

T001 is the first task in the feature and not a formality. SC-113 pins fixture accuracy unchanged **in
either direction**, and a baseline captured after the first edit measures the edit rather than the
starting point.

The direction matters more than it sounds. A refactor that accidentally *improves* detection is as
much a defect as one that degrades it: it means a structural change altered detection behaviour
nobody asked it to alter, and the improvement is unattributable — there is no way to tell which of
eight phases produced it, and no safe way to revert the phase that did. The next feature is detection
tuning, and it needs a baseline it can trust to be the product of deliberate choices.

The suite is red at baseline (24/41 positives, 8 false positives over 12 benign cases) and this
feature does not make it green. See `docs/002-accuracy-baseline.txt`.

## Why the two behaviour changes are separated

Phase 3 and Phase 4 both change what the tool does, and they must be separate commits because **they
fail differently**:

* Phase 3 makes a rule set that used to load fail to load. The symptom is at startup, in a caller's
  configuration, and it is loud.
* Phase 4 changes what a verdict says — a class name disappears from output, and `--classes encoding`
  becomes an error. The symptom is downstream, in whatever consumes the verdict, and it is quiet.

A single commit doing both gives a bisect one suspect for two unrelated symptoms. Separated, each
bisects to a commit whose message describes the symptom you are looking at.

## Why sealing is last

Sealing the verdict constructors (`pub(super)`) is the guarantee the feature exists for, and it is
tempting to do first so that everything after it is checked. It does not compile first. Every
construction site outside finalization has to be gone *before* the constructors stop being reachable
from outside, and removing those sites is most of Phases 2 and 5.

So the compile-fail cases (T010, T032) are written early and **fail** for most of the feature: the
code they forbid still compiles. That red is the intended state, and T063 is the commit that turns it
green. A compile-fail case that passes the day it is written is testing something other than what it
claims.

## Reconciliation with research P7

Two apparent divergences, both deliberate.

**Sealing is research step 9, but lands in Phase 5, before Phase 7's matcher merge.** "Sealing last"
means *after every construction site is gone*, not *after every other task in the feature*. What T063
seals is verdict construction. Phase 7 moves the prefilter and the pattern store into `matcher` and
its output is observations — by the end of Phase 5 nothing outside finalization builds a `Reason`, so
Phase 7 has nothing to seal against and is unaffected. The other half of step 9 — provenance kept
private, `validate_compiled` removed from the public surface — lands with Phase 3, because those
constructors are *created* sealed rather than sealed after the fact.

**The matcher merge is research step 6, but lands in Phase 7, after steps 7–8.** Steps 7 and 8 delete
duplicated logic in `engine.rs` (the parallel hit collection, the second reason sort). The matcher
merge also edits `engine.rs`, to remove index-based rule access. Doing the deletions first means the
merge has less code in front of it to move. Neither ordering is incorrect; this one moves less.

## Ordering constraints inside the feature

These are the dependencies that are not merely preference:

* **T007–T009 cannot be split.** Moving the verdict types is one commit or none — the types
  cross-reference each other, so they move together or the crate does not compile. This is the
  chokepoint the rest of the feature waits on.
* **Provenance before delta validation** (T033 → T039). You cannot validate only the untrusted rules
  until you can tell which rules are untrusted.
* **`Evidence` before anything recording into it** (T013 → T021, T022, T023).
* **Retention before pre-filling** (T038 → T075). The matcher cannot accept compiled patterns from
  preparation until preparation stops throwing them away.
* **Class removal before the score mapping** — or rather, inseparably with it. T049 exists because
  removing a `DetectionClass` variant breaks the exhaustive match in scoring. 001 refused a wildcard
  arm there specifically so this would be a compile error rather than a silently wrong corroboration
  bonus, and this is the payoff.

## Where to stop if time runs short

After Phase 4. At that point both defects shipped in 001 are closed — a resource bomb cannot produce
a scanner, and class selection works — and everything remaining is structural. Phases 5–7 make those
fixes hard to undo; they do not make them work.
