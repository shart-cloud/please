# Specification Quality Checklist: Structural Detection & Scan CLI

**Purpose**: Validate specification completeness and quality before proceeding to planning
**Created**: 2026-08-15
**Feature**: [spec.md](../spec.md)

## Content Quality

- [x] No implementation details (languages, frameworks, APIs)
- [x] Focused on user value and business needs
- [x] Written for non-technical stakeholders
- [x] All mandatory sections completed

## Requirement Completeness

- [x] No [NEEDS CLARIFICATION] markers remain
- [x] Requirements are testable and unambiguous
- [x] Success criteria are measurable
- [x] Success criteria are technology-agnostic (no implementation details)
- [x] All acceptance scenarios are defined
- [x] Edge cases are identified
- [x] Scope is clearly bounded
- [x] Dependencies and assumptions identified

## Feature Readiness

- [x] All functional requirements have clear acceptance criteria
- [x] User scenarios cover primary flows
- [x] Feature meets measurable outcomes defined in Success Criteria
- [x] No implementation details leak into specification

## Validation Record

Iteration 1 found two defects, both fixed before sign-off:

1. **FR-011 was not directly testable.** It required covering "the families represented in the
   evaluation corpus", which defers the requirement's meaning to an external document. Rewritten to
   name the five transformation families outright (base-64, hexadecimal, rotation cipher,
   reversal, glyph substitution), which are the ones carrying explicit corpus labels and are
   therefore independently measurable.
2. **FR-032 had no acceptance scenario.** Directory scanning and its summary status were required
   but never exercised by a Given/When/Then. Added as User Story 2, scenario 6.

Iteration 2 passed all items. A grep for implementation vocabulary — language names, serialisation
formats, matching-engine terms, package ecosystems, transport protocols — returns no hits. Counts at
sign-off: 4 user stories, 32 functional requirements, 12 success criteria, 0 clarification markers.

## Deliberate Choices To Review

These passed validation but encode judgement a reviewer should confirm rather than assume:

- **Accuracy criteria are stated against curated fixtures, not the public corpus.** SC-002 and
  SC-003 are fixture-based because corpus-scale stratified metrics need the evaluation harness,
  which is a separate feature, and because corpus text cannot be vendored under its licences. The
  consequence is that this feature can pass its own criteria while its real-world accuracy remains
  unmeasured until the evaluation harness lands.
- **The three-outcome verdict model adds an outcome every caller must handle.** Clean / risk found /
  inconclusive follows from constitution Principle I, but it does propagate into every downstream
  interface, and a caller that ignores the third case reintroduces the fail-open this was meant to
  prevent.
- **Multilingual is scoped as a false-positive concern only** (FR-010), with no detection claim,
  because the corpus contains zero non-English attack examples.

## Notes

- Items marked incomplete require spec updates before `/speckit-clarify` or `/speckit-plan`
