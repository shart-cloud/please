# Attribution

This project is built agent-first, and this document records who wrote what. The constitution makes it
a quality gate rather than a courtesy: provenance of the work is part of the record.

Two mechanisms, deliberately both:

1. **Commit trailers.** Every commit containing work authored by an AI agent carries a
   `Co-Authored-By:` trailer naming that agent. This is the machine-readable record — `git log` is the
   source of truth, and it cannot drift from what actually happened.
2. **This document.** A component-level summary, because reconstructing "who designed the score
   formula" from 116 commits is not a reasonable thing to ask a reader to do.

## How to read the split

"Agent-authored" means an AI agent produced the text or code. "Human-authored" means Jared Gore wrote
it. "Human-directed" is the most common and most important category: the agent produced the artifact,
but a human made the decision that determined its content — chose between options, rejected a
recommendation, set a constraint, or supplied the domain judgement the agent lacked.

The distinction matters because "the agent wrote 8,000 lines of specification" and "the agent wrote
8,000 lines of specification implementing decisions a human made" are very different claims, and only
the second one is true here.

## Component breakdown

| Component | Authorship | Notes |
|---|---|---|
| Project concept, scope, and goals | Human | The idea, the target integration points, and the decision to build something maintainable rather than a one-off |
| Name and binary name (`PLEASE`, `plz`) | Human, agent-checked | Acronym and repository name chosen by the human; the agent checked registry and PATH collisions and flagged the `pleaser` conflict |
| Dataset selection | Human | Chose the primary corpus from a shortlist the human had already researched |
| Corpus measurement (`docs/research/corpus-analysis.md`) | Agent | Measured against the dataset itself rather than its card; four of the six findings changed the plan |
| Constitution v1.0.0 | Agent, human-directed | Human set the scope constraints (injection only, moderation opt-in) and the attribution rule; agent drafted the principles |
| Feature 001 specification | Agent, human-directed | Human resolved five clarification questions and three analysis findings that determined FR-001a, FR-020, FR-028, FR-032a, SC-003, and SC-006 |
| Score aggregation formula | Human decision, agent design | Agent presented four options with a recommendation; human chose |
| Research decisions D1–D16 | Agent | Including the two that changed the design: quadratic match iteration, and cold start being the binding latency budget |
| Cross-artifact analysis | Agent | Found two constitution violations in the agent's own earlier work |
| Phase 1 scaffold | Agent | This commit |

*Sections below are filled in as the work lands (T112).*

## Detection rules

*Pending — `rules/builtin.toml` is authored at T057 and T058.*

Rule authorship is worth tracking separately from code. A rule encodes a judgement about what
constitutes an attack, and where that judgement came from — a published technique, a corpus sample, or
someone's intuition — is exactly what a reviewer needs in order to trust or challenge it.

## Engine implementation

*Pending — Phase 2 onward.*

## Fixtures

*Pending — T037–T043, T076, T077, T097.*

The 200-example hard-negative set (T043) deserves specific attention here. Positives are easy to
collect; the negatives that keep a firewall switched on are the hard part, and whoever assembles them
is making judgement calls about what "benign" means.
