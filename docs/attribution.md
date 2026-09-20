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

The September 18, 2026 larger Jev evaluation (`crates/eval/scripts/jev_scale/`
and its research reports/manifests) is Codex-authored and human-directed. It
reuses upstream public labels and earlier first-party contextual labels, freezes
source-stratified requests, and compares real Jev responses with the structural
product. It does not add independent label review or change shipping defaults.

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

## Feature 007 — Prompt-injection test bench

| Component | Authorship | Notes |
|---|---|---|
| Feature 007 specification, plan, research, contracts, and implementation tasks | Agent, human-directed | Human selected the goal of extending PLEASE into a comparative prompt-injection test bench while preserving the frozen feature-006 product behavior |
| `crates/eval/src/bench/` and `please-eval-bench-fixture` | Agent, human-directed | Agent implemented the identity-bound pack, adapter, runner, reporting, comparison, and exposure contracts under human review |
| `crates/eval/bench/contextual-reference.py` | Agent | Deterministic protocol fixture used to test contextual reporting; it is not represented as an independent defense or accuracy baseline |
| `crates/eval/corpus/bench/contextual-pilot/` | Agent, human-directed | First-party generated development pack. Labels are same-author and exposed; an independent second pass and untouched holdout remain explicitly outstanding |
| Feature 007 remediation review and plan | Agent, human-reviewed | Five-axis working-tree review; revision 2 incorporates the human author's corrections to the original findings |

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

## Feature 004 — The Judgement Tier

| Component | Authorship | Notes |
|---|---|---|
| Feature 004 specification, plan, research, tasks | Agent, human-directed | Human set the scope: a second opinion that arbitrates rather than detects |
| **D2 — `ureq` over `reqwest`** | **Human** | Human rejected adding a tokio runtime for a single POST. The agent measured the trees afterwards and the numbers agreed; the decision preceded the measurement |
| **D3 — credential precedence** | **Human** | Human supplied the live environment where `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_API_KEY` are both set with a proxy base URL. That configuration is what turns the ordering from a preference into a disclosure question, and the agent would not have found it |
| D4 — the model reports, we compute the score | Agent, human-directed | The anti-inflation argument is the agent's; the constraint that the tier must not be able to raise a severity is the human's |
| D9 — refusing to judge a truncated verdict | Agent | Found by reading `finalize`, not by reading the spec: the score is aggregated before truncation, so recomputing after it silently understates. A fail-open reachable by arithmetic |
| D10 — the vocabulary moves into `please-core` | Agent, human-directed | Human chose between three options after the agent laid out what each cost |
| **D4a — the axis, by measurement** | **Agent, and it refuted the agent's own hypothesis** | See below |
| Fail-closed paths and the adversarial property test | Agent | |
| Two spec contradictions found during implementation | Agent | US3 Scenario 1 against FR-404, and the claim that an unavailable judge exits 2 |
| Human decision to investigate the axis empirically rather than patch | Human | When T039 failed, the human chose "probe first, then decide" over "add a field and see". That choice is why the wrong hypothesis cost one experiment instead of a design |

### D4a is the entry worth reading

T039 — the criterion the whole tier exists for — failed on first contact, and the failure was not the
scoring function. Every answer the model gave was **correct**, and correct answers demoted a live payload,
because D4's questions were all at document scale and at document scale the two discriminating fixtures
genuinely are the same document.

The agent's hypothesis was that `addressed_to` belonged at span scale. **It was wrong**, and a probe said so
in one run: both fixtures answer `no_one_in_particular`. The question that works —
*is this excerpt what the document set out to show, or a passenger inside it?* — was the third candidate,
and it separated the pair 3/3 where the other two separated nothing.

Adding the field was still not enough. The fix, found by ablating the real schema one change at a time,
turned out to be **one line of the tool description**: naming the document before the excerpts frames every
excerpt as part of what the document shows. Reordered, the tier works 5/5.

The agent also wrote a comment claiming the `required` array order was load-bearing, having reordered it on
suspicion and not yet measured it. It is not (4/4 either way). That claim was corrected in the same commit
that made it, and is recorded here because writing an unverified claim into the spec is precisely the
failure mode this feature spent its time finding in the spec.

**None of this was reachable by argument.** Three hypotheses, two of them wrong, and the correct one is a
sentence most readers would skim. The human instruction that made it findable was *"investigate the axis
empirically first"* rather than *"add a per-span field and re-test"* — which was on the table and would have
produced a tier that failed for a reason nobody had characterised.

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

## Benchmark presentation (2026-09-14)

Codex implemented the evaluator's shared terminal/HTML results presentation, Ratatui saved-run browser,
CLI integration, documentation, and presentation tests at Jared Gore's request. This adds presentation
of existing verified metrics; it does not change detection rules or benchmark labels.

Codex also connected corpus evaluations to HTML/TUI presentation and recorded the September 14
InjecAgent, LLMail-Inject, and OR-Bench product-mode measurement at Jared Gore's request.

## Detection improvement experiments (2026-09-14)

Codex authored the named-data email transmission rules, their positive/benign/property tests,
the evaluator-only frozen-input runner and reproduction scripts, and the
[measured experiment record](research/detection-improvement-2026-09-14.md) at Jared Gore's request.
Public corpus labels and bytes were preserved; generated test cases are first-party engineering
fixtures. The record distinguishes rejected experiments, exposed development data, and final
within-source validation. Existing uncommitted presentation work was preserved.

## Detection review response (2026-09-14)

At the user's review request, Codex withdrew the two email rules from built-in defaults,
preserved their historical evidence, and authored the
[review response](research/detection-review-response-2026-09-14.md) and separate
[role-marker follow-up](research/role-marker-prefilter-follow-up-2026-09-14.md).
The ten supplied controls retain reviewer-authored labels; the reviewer's identity
and any independent label review are unspecified. Codex authored and self-reviewed
the new paired task scenarios; no independent review of those labels is claimed.
They are exposed development checks, not an unseen-family effectiveness estimate.

## Matching consistency and prefilter cost (2026-09-15)

Codex authored the literal-admission audit, generated syntax controls, five-rule paired checks,
performance attribution, and freeze-first within-source validation at the user's request.
The [matching audit](research/matching-consistency-2026-09-15.md) and
[performance follow-up](research/prefilter-cost-2026-09-15.md) retain their separate detector identities,
authorship limits, rejected candidates, and exposure records. The current literal compaction preserves
the accepted matching coverage. No independent label review is claimed.

On resumption, Codex verified all 51 retained native runs, restored the performance report's missing
JSON/HTML and rule snapshots, connected the Python report regressions to CI, and updated the handoff.

## Shared saved-run storage (2026-09-15)

At the user's request to implement remediation Phase 4.1, Codex extracted evaluator saved-run storage,
moved bench aggregation under metrics, and added publication and wire-compatibility regressions.
Existing corpus and bench manifest shapes, result bytes, metric semantics, and percentage rounding
were preserved. Compatibility checks re-read 51 retained corpus runs and two bench runs with old and
new readers; they did not rescan prompts or constitute new detector effectiveness evidence.

## Lightweight decision-model pilot — 2026-09-16

Human-directed, Codex-authored: isolated GLiClass benchmark adapter, pinned environment/model manifest, source-stratified comparison tooling, contract/parity checks, and research report. Jared proposed exploring lightweight contextual decision models against Please. No shipping detection behavior was modified.

## Decision-model phase 2 planning - 2026-09-16

At Jared's request, Codex researched the next lightweight-model experiment, audited the saved GLiClass score distributions, and authored the [phase 2 plan](research/decision-model-phase-2-plan-2026-09-16.md) and metadata-only research manifest. The plan and proposed gates are not new model results; no phase-2 model was run and no shipping behavior changed.

After Jared confirmed Colab Pro access, Codex added a resumable cloud-training path and retained local deployment benchmarks and independent holdout separation. No cloud training or data transfer was performed.

Codex authored the [next-steps handoff](research/decision-model-next-steps-handoff-2026-09-16.md) at Jared's request, documenting the current checkout, retained evidence, Phase 2A implementation order and later Colab training path.

## Decision-model Phase 2A implementation - 2026-09-16

At Jared's request, Codex authored the isolated G1/N1/N2 adapters, frozen recipes and asset manifests, contract/parity tests, generated development and calibration packs, self-reviewed control labels, and native-run reporting. Generated labels are same-author development evidence; independent review and a fresh holdout remain outstanding. Existing Phase 1 work and failed setup attempts were preserved. No shipping code or cloud training was changed.

## TypeSafe Jev advisory integration - 2026-09-16

After Jared obtained TypeSafe access, he requested Jev integration into plz. Codex authored the optional Jev client, caller-context validation, bounded HTTP transport, advisory CLI command, offline contract/property/HTTP tests and setup documentation. No release authority is granted and no live provider evaluation is claimed. At Jared's request, Codex added `plz clap` as an alias for `plz jev`, correcting the initial shell-alias interpretation.

## Jev live development comparison - 2026-09-16

At Jared's request, Codex used a temporary in-memory TypeSafe credential to compare the frozen Jev recipes against all 1,950 previously tested synthetic/public cases. The isolated network-enabled evaluator preserves exact inputs, native verified runs, original failures, bounded follow-up diagnostics, and source-stratified comparisons. Contextual tests invoked the captured plz clap CLI; artifact tests used a separate benchmark-only Choice prompt. No thresholds or shipping enforcement changed, and no independent holdout is claimed.

## Jev contextual follow-up - 2026-09-16

At Jared's request, Codex froze and ran four contextual variants on 120 existing synthetic cases and 36 new analysis-versus-redirection regressions. The isolated evaluator separates representation changes, focused questions and additional caller facts with deterministic guards. Twelve contract tests and the 624-row native capture replay verified. No variant passed screening, so the predeclared 600-case confirmation was not run. Original failures, one setup correction and one assistant-caused authentication failure remain preserved. No shipping recipe or enforcement policy changed.

## Jev usage-pattern experiments - 2026-09-16

At Jared's request, Codex authored and froze four API recipes and a shared-response decoder comparison, then ran 816 requests over 204 synthetic development cases. Forty-eight new rows were authored and self-reviewed before inference. Fourteen offline checks and the 1,020-row native replay passed. Caller-directed concise questions improved measured performance but no candidate passed every screening gate; confirmation was not run. The report preserves all responses, rejected components, prior data and a failed offline preflight. No shipping behavior changed; independent review and fresh holdout remain outstanding.

## Interactive Jev workspace - 2026-09-16

At Jared's request, Codex turned the personal-input Jev workflow into an interactive CLI feature: text/file input, caller-owned context, explicit provenance, local request preview, masked in-memory credentials, asynchronous advice, and non-overwriting JSON export. Bare terminal invocation of plz clap / plz jev opens the TUI; explicit script invocation retains JSON. The presentation feature is optional and does not link the evaluator or change the advisory recipe. Codex added UI/CLI/transport tests, credential-reflection protection, terminal dependency isolation checks and documentation. Full workspace credential-canary tests, Clippy, offline and JSON-only configurations, core/dependency/WebAssembly checks, render checks and actual terminal smoke tests passed. One synthetic live TUI request completed; credentials were absent from terminal output and the saved result. The installed binary preserves byte-identical ordinary scan output and exit status on three regression fixtures.

At Jared's request, Codex authored the [Jev/TUI continuation handoff](research/jev-next-steps-handoff-2026-09-16.md), capturing the installed feature, verified evidence, uncommitted checkout, research limits and proposed next steps. The handoff does not promote a research recipe, start another experiment or create a new task.

## Jev local files and review preparation - 2026-09-17

Following Jared's continuation handoff, Codex authored named local context
presets, strict bounded saved-advice parsing, offline read-only viewing,
CLI entry points, regression/property tests and documentation. The shipping
recipe and thresholds are unchanged. Codex also authored a model-outcome-free
analysis/redirection review packet and blank response template. Independent
labels remain pending; this packet is not a blind holdout. No provider
inference, threshold tuning, commit or push was performed.

The continuation passed the full workspace credential-canary suite, Clippy,
feature/dependency/core/WebAssembly checks, offline file contracts and actual
terminal tests. Codex installed the verified release after preserving the old
binary; scanner output and exact Jev requests matched the prior version.

## Native framework model evaluation — 2026-09-18

At Jared's direction, Codex added an optional Jev test-bench adapter using the existing
`please-judge::jev` client shared by `plz jev` / `plz clap`. Jared explicitly chose to validate a
Candle classification implementation before benchmarking GLiNER2. Codex authored the Rust
classification adapter, bounded protocol, model/recipe locks, synthetic parity fixtures,
preparation tooling, and documentation. The schema compiler and Unicode word splitter follow
Fastino's Apache-2.0 GLiNER2 implementation; model inference uses Hugging Face Candle. The
Python GLiNER2 library is an isolated numerical reference, not the benchmark runtime. These
changes remain in the excluded evaluator and do not promote a model into shipping detection.

Upstream sources: [GLiNER2](https://github.com/fastino-ai/GLiNER2),
[pinned model](https://huggingface.co/fastino/gliner2-base-v1/tree/79c3a777abc572b4767922f3916cf63fb5754df2),
[Candle](https://github.com/huggingface/candle).

## Laya source review — 2026-09-19

At Jared's request, Codex inspected pinned Laya source and small model configuration files, compared them with the current Please benchmark and Jev contracts, and authored the [integration assessment](research/laya-integration-assessment-2026-09-19.md). This was a source review only: no weights, dependency installation, inference, shipping code or defaults changed.

## Laya measured development experiment — 2026-09-19

At Jared's request, Codex authored and ran an isolated local Laya evaluation: two pinned checkpoints, original Jev and compact question sets, a frozen 1,200-public/600-contextual sample, and three diagnostic controls. The 7,560 reported model/recipe rows use native benchmark verification and matched historical Jev evidence without additional Jev requests. Offline contracts, tokenizer parity, synthetic repeatability and exact token boundaries were checked. Original protocol failures and zero-response startup attempts remain retained; same-limit retries are explicitly indexed. No shipping defaults, environment packages, training or calibration were changed. All data remains exposed development evidence; independent review and a fresh holdout are outstanding.
