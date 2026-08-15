# Feature Specification: Trustworthy Core — Rule Preparation & Verdict Finalization

**Feature Branch**: `002-trustworthy-core`

**Created**: 2026-08-15

**Status**: Draft

**Input**: Architecture review of the 001 implementation. Two transitions — rules into executable state, and
evidence into a verdict — are currently spread across four modules with no owner. One of them is a live
safety gap rather than untidiness: the validation that Feature 001 specified has **zero call sites**.

## Clarifications

### Session 2026-08-15

- Decision: `DetectionClass::Encoding` is **removed**. Delivery is not a detection class — a payload
  recovered by decoding is a finding of whatever class the rule that matched it declares, and the decoding
  is recorded in the transform chain. Rationale: no rule can declare class `encoding` (the built-in set has
  zero such rules), so the class named a *mechanism* while research D5 states an encoding is never itself a
  finding. The contradiction is what produced the double-gate defect.
- Decision: preparation and finalization ship as **one feature** rather than two, for delivery speed. They
  remain separable in implementation and their tasks are ordered so preparation — which closes the safety
  gap — lands first.
- Decision: disabled rules **are** subject to resource validation. `enabled` is data a caller can flip, so
  skipping them would let a validated rule set silently become unvalidated with no construction occurring.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A supplied rule set cannot produce an unsafe engine (Priority: P1)

A team points the scanner at their own rule file. Whether that file is well-intentioned, mistaken, or hostile,
they need the outcome to be binary: either the rule set is rejected with a diagnostic naming the offending
rule, or every rule in it has been proven to compile within its resource budget before anything can be
scanned. There is no third state in which scanning proceeds with rules of unknown cost.

**Why this priority**: This is the only story that closes an open safety gap rather than improving structure.
Feature 001 specified whole-set rejection for malformed and resource-exhausting rule sets; the check exists
as a callable operation that **nothing calls**, so today a rule set containing a counted-repetition
expansion builds a working engine and degrades rule-by-rule during scanning instead. Everything else in this
feature is a refactor; this is a defect.

**Independent Test**: Attempt every public engine-construction path with a rule set containing a resource
bomb and assert construction fails. Then attempt the same paths with a legitimate rule set and assert they
succeed. No ordering discipline, no optional pre-step.

**Acceptance Scenarios**:

1. **Given** a caller-supplied rule set containing a rule whose compiled form exceeds the resource budget,
   **When** an engine is constructed by any public path, **Then** construction fails with a diagnostic naming
   the offending rule, and no engine capable of scanning exists.
2. **Given** the same rule set, **When** a caller looks for a construction path that omits resource
   validation, **Then** none exists — validation is not a step a caller can forget, defer, or order wrongly.
3. **Given** a legitimate caller-supplied rule set, **When** an engine is constructed, **Then** construction
   succeeds and the work done to prove the rules safe is **retained**, so no rule is compiled twice.
4. **Given** a rule set whose only defective rule is marked disabled, **When** an engine is constructed,
   **Then** construction still fails: validation covers every rule present, so later enabling one cannot
   invalidate an already-constructed engine.
5. **Given** limits tightened below those a rule set was validated against, **When** an engine is
   constructed with those limits, **Then** the rule set is revalidated rather than trusted.

---

### User Story 2 - Every detection class is independently addressable (Priority: P1)

A caller narrows scanning to the classes they care about. Selecting a class must find everything of that
class, whatever route it arrived by, and deselecting a class must not silently disable others.

**Why this priority**: Also a defect, not a refactor, and currently observable from the command line: a
base-64-encoded override is detected under the default policy, and reported **clean** when either
`override` or `encoding` is selected alone, because a decoded finding must pass two independent class gates.
FR-015 promises independent addressability and does not hold.

**Independent Test**: For each detection class, scan a payload of that class with only that class active and
assert it is found. Includes payloads delivered in the clear and by decoding.

**Acceptance Scenarios**:

1. **Given** a payload whose rule declares class C, delivered in the clear, **When** scanned with only class
   C active, **Then** it is detected.
2. **Given** the same payload delivered base-64 encoded, **When** scanned with only class C active, **Then**
   it is detected — the delivery mechanism does not change the finding's class.
3. **Given** the same encoded payload, **When** scanned with class C deactivated, **Then** it is not
   reported, regardless of how it was delivered.
4. **Given** any finding recovered by decoding, **When** the verdict is inspected, **Then** the
   transformation chain records how it arrived, and no detection class names a delivery mechanism.

---

### User Story 3 - One place decides what a verdict says (Priority: P2)

A maintainer changing how evidence is weighed — adding corroboration rules, a document-shape signal, a
confidence distinct from severity — needs one place to change it, and needs to be unable to break the
fail-closed guarantee by forgetting a step somewhere else.

**Why this priority**: It is a refactor, so it ranks below the two defects. It ranks high among refactors
because the next iteration of accuracy work touches this transition repeatedly, and the current shape makes
every experiment an edit in several places with a real chance of introducing another
two-things-that-must-agree defect.

**Independent Test**: Construct evidence directly — observations and coverage gaps, including combinations a
real scan cannot easily produce — and assert the resulting verdict. No engine, no rules, no input.

**Acceptance Scenarios**:

1. **Given** observations and coverage gaps, **When** a verdict is produced, **Then** exactly one component
   was capable of producing it.
2. **Given** a detector that observes something, **When** it attempts to construct a reported reason, a
   coverage gap record, or a verdict directly, **Then** it cannot — observations are the only currency a
   detector deals in.
3. **Given** a scan in which more observations were made than the reported limit allows, **When** the score
   is computed, **Then** it reflects every observation, and this holds without any component maintaining a
   second parallel collection.
4. **Given** any scan, **When** reported reasons are ordered, **Then** exactly one definition of that order
   exists.
5. **Given** a coverage gap of any kind from any detector, **When** it is recorded, **Then** it is expressed
   in one shared vocabulary rather than translated from a detector-specific shape by its caller.

---

### User Story 4 - The effect of quoting suppression is observable (Priority: P3)

An engineer investigating false positives needs to know what the quoting heuristic hid. Today that requires
running the same scan twice with different options and diffing the output.

**Why this priority**: It is the smallest story and the one that most directly serves the open accuracy
problem. Suppression is the principal lever on the security-prose false positives, and its effect is
currently unmeasurable in a single run — the suppressed observations are computed and then discarded.

**Independent Test**: Scan content containing a payload inside a quoting context and assert the verdict
records what was suppressed and why, in a single run.

**Acceptance Scenarios**:

1. **Given** an observation inside a quoting context, **When** it is suppressed, **Then** the suppression and
   its context are recorded rather than discarded.
2. **Given** a verdict, **When** an engineer asks what suppression changed, **Then** the answer is present in
   that verdict without re-running the scan.
3. **Given** suppression disabled by policy, **When** the scan runs, **Then** previously suppressed
   observations are reported and annotated with the context that would have hidden them.

---

### User Story 5 - Rule identity cannot drift between components (Priority: P3)

A maintainer reordering, filtering, or partitioning rules must not be able to cause a real match to be
reported with another rule's identity, severity, or description.

**Why this priority**: A latent hazard rather than a live defect — three components currently agree on an
array position, and they agree today only because one function builds all three from the same list. Nothing
enforces it. The failure mode is silent and severe: correct detections attributed to the wrong rule, which no
existing test would catch.

**Independent Test**: Verify no component outside the one owning rule storage can observe or construct a
positional rule identifier.

**Acceptance Scenarios**:

1. **Given** the components that select, evaluate, and report on rules, **When** their interfaces are
   examined, **Then** no rule position is exchanged between them.
2. **Given** a change that reorders or filters rules, **When** the code is compiled, **Then** any component
   that had assumed a position either fails to compile or is unaffected by construction.

---

### Edge Cases

- A caller-supplied rule set that is entirely valid but very large: validation cost must be proportional to
  the **caller's** rules, not to the union with the built-in set.
- A caller-supplied rule set that replaces a built-in rule: the replacement is untrusted and must be
  validated; the displaced built-in rule leaves the set entirely.
- A caller-supplied rule set consisting only of suppressions: removing rules cannot introduce a resource
  problem, so no compiled validation is required — but suppressing an unknown rule remains an error.
- The built-in rule set under tightened limits: its pre-established validity no longer applies.
- A caller who names their own rule set identically to the built-in one: must not thereby obtain the
  built-in's trusted treatment.
- A verdict produced before this feature and one produced after, for identical input and rules: the identity
  recorded must make the difference in provenance and validation state visible rather than silently equal.
- A detection class removed from the model: verdicts and rule sets referring to it must fail loudly rather
  than be silently reinterpreted.

## Requirements *(mandatory)*

### Preparation: safety by construction

- **FR-101**: Rule preparation MUST be owned by a single component responsible for parsing, resolution,
  identity, resource validation, provenance, and the creation of executable matching state.
- **FR-102**: No executable scanning capability MUST be obtainable from caller-supplied rules unless
  compiled resource validation of those rules has succeeded.
- **FR-103**: FR-102 MUST hold without depending on caller call order, on an optional preliminary step, or on
  documentation. A construction path that omits validation MUST NOT exist.
- **FR-104**: Rule provenance MUST be recorded and MUST NOT be forgeable by a caller. A caller MUST NOT be
  able to obtain the treatment reserved for the built-in rule set by any means, including naming.
- **FR-105**: Provenance MUST survive resolution at the granularity of individual rules, so that validation
  can be applied to caller-supplied rules alone.
- **FR-106**: Compiled resource validation of the built-in rule set MUST be established by a check that runs
  in continuous integration, and MUST NOT be repeated per invocation at its validated limits.
- **FR-107**: Resource validation MUST cover every rule present in a resolved rule set, including rules
  marked disabled.
- **FR-108**: A validation record MUST identify the limits it was performed against. Constructing an
  executable capability with limits stricter than those MUST trigger revalidation.
- **FR-109**: Work performed to prove a rule safe MUST be retained and reused as executable matching state.
  No rule MUST be compiled more than once per prepared rule set.
- **FR-110**: Suppression of rules MUST require no compiled validation. Suppressing an identifier that is not
  present MUST remain an error.
- **FR-111**: Rule-set identity MUST reflect provenance and validation state in addition to content, so that
  two rule sets differing only in trust origin are distinguishable.

### Finalization: one owner for the verdict

- **FR-120**: The transition from observations and coverage gaps into a verdict MUST be owned by a single
  component, and that component MUST be the only thing capable of producing a verdict.
- **FR-121**: Detectors MUST express findings as observations only. A detector MUST NOT be able to construct
  a reported reason, a coverage-gap record, or a verdict.
- **FR-122**: Coverage gaps MUST be expressed in one shared vocabulary at the point where the gap occurs. No
  component MUST translate detector-specific shapes into that vocabulary on a detector's behalf.
- **FR-123**: The judgement of what constitutes a coverage gap MUST NOT reside in a decoder or matcher.
- **FR-124**: Score aggregation over all observations, followed by truncation of reported reasons, MUST be
  guaranteed structurally rather than by a discipline of keeping two collections consistent.
- **FR-125**: Exactly one definition of the ordering of reported reasons MUST exist.
- **FR-126**: The transition from an observation to a reported reason, including excerpt neutralisation and
  any coverage gap that neutralisation produces, MUST reside with the verdict owner.
- **FR-127**: Where a verdict's score or risk is not derived from the caller-provided value, that MUST be a
  property of the owning component rather than a silent adjustment invisible at the call site.
- **FR-128**: Suppressed observations MUST be retained as evidence, together with the context that suppressed
  them, and MUST be reportable within a single scan.
- **FR-129**: An analysis plan MUST resolve the active detection classes exactly once, and every subsequent
  stage MUST rely on that resolution rather than re-deciding it.

### Class model and independent addressability

- **FR-130**: Detection classes MUST name kinds of finding, never delivery mechanisms.
- **FR-131**: `Encoding` MUST be removed as a detection class. A finding recovered by decoding MUST carry the
  class declared by the rule that matched it.
- **FR-132**: The delivery mechanism of a finding MUST be recorded in its transformation chain.
- **FR-133**: The active-class filter MUST be applied exactly once per observation, to the class that
  observation carries.
- **FR-134**: Selecting a single detection class MUST find every finding of that class regardless of delivery
  mechanism. Deselecting a class MUST NOT affect findings of other classes.
- **FR-135**: Disabling decoding MUST remain achievable through the existing depth bound rather than through
  class selection.

### Rule identity

- **FR-140**: No positional rule identifier MUST be exchanged between components. The component owning rule
  storage MUST own the position space privately.
- **FR-141**: Components that select, evaluate, and report on rules MUST refer to rules by stable identity
  rather than by position.

### Amendments carried from Feature 001

- **FR-150**: Feature 001's FR-024 MUST be amended to require resource limits on rule sets. A
  resource-exhausting rule is well-formed, so a requirement covering only malformed rule sets does not
  describe the behaviour the implementation provides.
- **FR-151**: Feature 001's SC-004 MUST be amended to state the warm per-scan budget and the cold-start
  budget separately, as they have different causes and different remedies.
- **FR-152**: Published documentation of the embedding surface MUST be corrected where it no longer matches
  the implementation, including the claim that an engine may be cloned.

### Key Entities

- **Prepared rule set**: a rule set that has been parsed, resolved, identified, and — for every
  caller-supplied rule — proven to compile within its resource budget, together with the executable matching
  state produced by that proof and the limits the proof was performed against. The only thing an executable
  scanning capability can be built from.
- **Provenance**: the trust origin of a rule or rule set — shipped with the tool, or supplied by a caller.
  Recorded, not asserted; unforgeable by a caller.
- **Validation record**: evidence that resource validation succeeded, and the limits it succeeded against.
  A state, not the result of a check that was discarded.
- **Analysis plan**: what a given scan will examine, derived once from policy and the prepared rule set —
  active classes, participating rules, bounds. Consulted by later stages, never re-derived.
- **Observation**: something a detector saw — its class, severity, location, matched content, and the
  transformation chain by which it arrived. A detector's only output.
- **Coverage gap**: something a scan did not examine, recorded in a shared vocabulary at the point it
  occurred, by the code that knows why.
- **Evidence**: the accumulated observations, coverage gaps, and suppressions of one scan. Written by
  detectors and orchestration; read only by the verdict owner.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-101**: 100% of public construction paths reject a caller-supplied rule set containing a
  resource-exhausting rule, and 0% produce a scanning capability from one.
- **SC-102**: No construction path exists that produces a scanning capability from unvalidated
  caller-supplied rules, demonstrated by enumerating every such path.
- **SC-103**: For each of the five detection classes, a payload of that class is detected when only that
  class is active — both when delivered in the clear and when delivered by decoding. 10 of 10 combinations.
- **SC-104**: Cold start for the built-in rule set does not regress: process launch to first verdict remains
  within the budget stated in Feature 001.
- **SC-105**: Validation cost for a caller-supplied rule set is proportional to the number of caller rules,
  not to the size of the resolved set. Adding one rule to the built-in set costs measurably less than
  validating the whole set.
- **SC-106**: No rule is compiled more than once per prepared rule set, demonstrated by counting
  compilations.
- **SC-107**: Exactly one component can produce a verdict, and exactly one definition of reason ordering
  exists, both demonstrated by enumeration.
- **SC-108**: A detector attempting to construct a reported reason, a coverage-gap record, or a verdict fails
  to build.
- **SC-109**: Score-reflects-all-observations holds without any component maintaining a second parallel
  collection of observations.
- **SC-110**: An engineer can determine what quoting suppression changed for a given input from a single
  scan's output.
- **SC-111**: No rule position is exchanged between components, demonstrated by enumerating their interfaces.
- **SC-112**: Every test that passed before this feature either still passes, or was replaced by a test of
  the same behaviour at a more precise interface, with the replacement recorded.
- **SC-113**: Accuracy against the fixture corpus does not regress: detection and false-positive counts are
  recorded before and after, and any change is accounted for.

## Assumptions

- **This feature changes structure and closes a safety gap; it does not attempt to improve detection
  accuracy.** The security-prose false positives identified in Feature 001 remain open and are expected to be
  addressed separately. SC-113 exists to ensure this work neither improves nor degrades accuracy by accident,
  so that the accuracy work that follows starts from a known baseline.
- Preparation and finalization are independent and could have shipped separately. They are combined for
  delivery speed, and task ordering places preparation first because it closes the safety gap.
- The built-in rule set's validity is assumed establishable in continuous integration. That check does not
  currently exist, so it is part of this feature rather than an existing guarantee — the fast path's safety
  presently rests on nothing.
- Removing a detection class is assumed to be acceptable to any existing consumer, because none exists: the
  machine-readable output contract has not been published and the class in question has never been declarable
  by a rule.
- The measured figures this design rests on — roughly 4 ms to validate syntax and 44 ms to compile 80 rules —
  are assumed still representative. They were measured on the development host and are the reason the
  built-in set keeps a fast path at all; a substantial change would justify revisiting the split.
- Retaining compiled matching state is assumed to have acceptable memory cost for rule sets of the expected
  size. Rule sets large enough for this to matter would already exceed the rule-count limit.
