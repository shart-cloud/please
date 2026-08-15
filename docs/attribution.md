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

## Feature 002 — Trustworthy Core

| Component | Authorship | Notes |
|---|---|---|
| Feature 002 specification, plan, research, tasks | Agent, human-directed | Human directed the scope: close the two shipped defects first, keep the refactors behind them |
| Phases 1–7 implementation | Agent, human-directed | Human chose the phase order and approved each phase before the next |
| `Provenance` as a newtype over a private enum | Agent | Research P1. A public enum's variants are publicly constructible, so the obvious spelling cannot express the guarantee |
| Verdict types moving *inside* `finalize` | Agent | Research P3. Forced rather than chosen: `pub(in crate::finalize)` cannot be written from outside that tree |
| Delta validation | Agent, human-directed | Human's constraint that a `--rules` flag must stay usable is what made cost-proportional-to-caller-rules a requirement rather than an optimisation |
| Decision to seal in Phase 2 rather than Phase 5 | Agent | Divergence from the plan, argued in `docs/002-migration.md`; the precondition is met three phases earlier than the plan assumed |
| Rejecting the shell-prompt heuristic | Human-directed, agent-evaluated | **Human proposed it and asked for it to be evaluated before adoption.** The agent implemented, measured, found it suppresses a real injection in the corpus, and rejected it. The instruction to evaluate first is what prevented a two-character evasion of the structural tier |
| Apostrophe mis-pairing in the quoting pass | Human-found, agent-fixed | **Human identified the defect by inspection** — asked whether a contraction between an intended open and close quote makes `find_close` match the wrong byte. It does. The agent confirmed it in `benign-security-prose-003` and fixed it |
| Leetspeak suppression bypass | Agent, human-directed | Human directed the leetspeak evaluation. Agent found that a whole-input fold is a copy of the document that quoting suppression does not cover, and gated it on evidence of deliberate substitution: false positives 8 → 1 |
| Detection-work sequencing | Human | Human's decision to land detection improvements as a group alongside 002 rather than deferring them |

Two entries above are worth reading together, because they are the same lesson from both directions: a human
proposal that measurement rejected, and a human inspection that found a defect the agent's own tests had
missed. Neither would have been caught by the other party working alone.

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
