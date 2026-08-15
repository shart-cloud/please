<!--
Sync Impact Report
==================
Version change: (uninitialized template) → 1.0.0
Bump rationale: Initial ratification. First concrete version of the project constitution.

Modified principles: N/A (initial adoption). Template placeholders replaced with:
  I. Judgement Is Separate From Enforcement
  II. Bounded, Linear-Time Analysis
  III. Detection Rules Are Data, Not Code
  IV. Evaluation Is Stratified And Honest
  V. Embeddable, Dependency-Free Core

Added sections:
  - Scope & Analysis Constraints (replaces [SECTION_2_NAME])
  - Development Workflow & Quality Gates (replaces [SECTION_3_NAME])

Removed sections: None.

Templates requiring updates:
  ✅ .specify/templates/plan-template.md — "Constitution Check" reads gates dynamically; no
     hardcoded principle names. Plan authors MUST populate gates from Principles I–V plus the
     constraints in both named sections below.
  ✅ .specify/templates/spec-template.md — principle-agnostic; no change required.
  ✅ .specify/templates/tasks-template.md — principle-agnostic; no change required.
  ✅ .claude/skills/speckit-*/SKILL.md — load the constitution generically; no stale references.

Deferred items: None. Ratification date set to project creation date (2026-08-15).

Evidence base: docs/research/corpus-analysis.md records the measured corpus facts that Principles
II and IV encode. Amendments to those principles SHOULD cite re-measured evidence.
-->

# PLEASE Constitution

PLEASE — Prompt-Layer Evaluation And Security Engine — detects prompt-injection attempts in text
reaching an AI agent, and measures how well it does so. It ships a Rust engine that harnesses
embed, a `plz` binary that hooks shell out to, and an evaluation harness that produces the numbers
backing every accuracy claim.

## Core Principles

### I. Judgement Is Separate From Enforcement

The engine returns a verdict; it never decides an outcome. A verdict MUST carry the assessed risk,
a calibrated score, and the machine-readable reasons that produced it. Deciding whether a given
verdict blocks, warns, logs, or passes is the caller's policy, expressed in configuration the
caller owns.

Absence of detection MUST NOT be reported as absence of risk. When analysis cannot complete — the
input exceeded a cap, a decoder bailed out, an optional tier was unavailable, a rule set failed to
load — the verdict MUST be an explicit indeterminate state naming the reason, never a clean
verdict. A caller MAY choose to treat indeterminate as passing; the engine MUST NOT make that
choice on the caller's behalf.

Rationale: A detector that silently downgrades "I could not analyse this" to "this is fine" fails
open at exactly the moment an attacker has arranged for it to. Keeping enforcement in the caller
is also what lets one engine serve a blocking pre-tool hook, a reporting CI job, and a research
sweep without forking its behaviour.

### II. Bounded, Linear-Time Analysis

A security tool MUST NOT become a denial-of-service vector against the host it protects. Every
detector MUST run in time linear in its input length. Backtracking regular expressions are
forbidden; pattern matching MUST use an engine with linear-time guarantees. Recursive analysis —
nested decoding, unwrapping, re-scanning — MUST carry an explicit depth bound.

Every input MUST have a configured maximum size with a defined over-cap verdict per Principle I.
Throughput budgets are expressed per kilobyte, measured by benchmarks in CI, and are gates rather
than aspirations. Detectors MUST be fuzzed; a panic, hang, or unbounded allocation on any input is
a defect of the same severity as a missed detection.

Rationale: Measured inputs reach 82 KB in the evaluation corpus alone, and real scan targets — a
skill file, a fetched page, a tool result — are larger. A scanner sitting in the hot path of every
tool call is trivially weaponised if its cost is superlinear in attacker-controlled text.

### III. Detection Rules Are Data, Not Code

Detection rules MUST be declarative, human-readable, versioned, diffable text. A rule's meaning
MUST be reviewable in a pull request without running it. Rule sets MUST be loadable at runtime and
MUST be versioned and identified in every verdict, so any result can be traced to the exact rules
that produced it.

Compiled or optimised rule representations are derived artifacts and MUST NOT be authored directly.
A detector whose behaviour cannot be expressed as data MUST justify itself in writing as an engine
rather than a rule, and MUST still be independently addressable and disableable.

Rationale: A rule corpus is the part of a detector that changes weekly and that users need to
audit, extend, and override. Rules buried in Rust are neither reviewable by the people who must
trust them nor updatable without a release.

### IV. Evaluation Is Stratified And Honest

Accuracy claims MUST be reproducible from a committed manifest and MUST be reported per source
stratum, never as a bare aggregate. Where one source dominates a corpus, an aggregate score is a
score on that source and MUST NOT be presented as a general result.

False-positive rate is a first-class gate, not a footnote: CI MUST enforce a maximum false-positive
rate against a designated hard-negative corpus, and true-positive rates MUST be reported at that
fixed operating point. Known evaluation gaps — populations for which the corpus contains no
positive examples, techniques labelled on only a fraction of rows — MUST be stated explicitly
alongside the metrics rather than left for a reader to infer.

Corpus text under third-party licence MUST NOT be vendored into this repository. The repository
carries manifests — identifiers, labels, source, and content hashes — sufficient to verify a run
without redistributing the data.

Rationale: A firewall with an unmeasured false-positive rate gets switched off, which is a worse
outcome than never shipping it. And an aggregate number over a corpus half-supplied by one source
is not a claim that survives being asked how it was computed.

### V. Embeddable, Dependency-Free Core

The core engine is a library that harnesses embed; the CLI is a thin wrapper over the same public
entry points and MUST NOT contain detection logic the library lacks. The core MUST NOT require an
async runtime, MUST NOT perform network I/O, and MUST NOT require a downloaded model to return a
verdict at its default tier. It MUST compile to `wasm32-unknown-unknown`, and CI MUST prove that
on every change.

Heavier capability — classifiers, model-backed judgement, corpus tooling — MUST be additive and
opt-in, gated so that a build selecting none of it carries none of its dependencies. A guard test
MUST enforce that gating rather than trusting review to catch a regression.

Rationale: The engine's target callers are a Rust harness that forbids a forced runtime, a
pre-tool hook that must answer in milliseconds, and a browser. Any of those is lost the moment the
default build needs a runtime, a network call, or a model download — and a network dependency in a
security path is a fail-open waiting to happen.

## Scope & Analysis Constraints

- **In scope**: detection of prompt-injection and instruction-hijacking attempts in text reaching
  an agent — direct user turns, and indirect content arriving via files, skills, tool results,
  fetched pages, and tool or server descriptions.
- **Out of scope by default**: harmful-content moderation. It is a distinct problem with distinct
  corpora and distinct consumers. It MAY ship as an opt-in tier that reports and MUST NOT block by
  default. PLEASE is a firewall, not a content moderator, and conflating the two makes both
  metrics meaningless.
- **Tiered detection**: capability is organised in tiers of increasing cost and dependency weight.
  The default tier MUST be structural and dependency-free per Principle V. Model-backed and
  judgement tiers MUST sit behind explicit opt-in, MUST be addressable as independent detectors,
  and MUST degrade to an indeterminate verdict per Principle I when unavailable — never to clean.
- **Indirect injection is a first-class case, and under-covered by public data.** The measured
  agentic share of available positives is under one percent. Coverage of the artifact-scanning
  case therefore requires a purpose-authored corpus, which MUST be reported separately from
  public-corpus metrics and never blended into them.
- **Multilingual detection is a declared gap.** No non-English positive examples exist in the
  primary corpus. Multilingual performance MUST NOT be claimed or implied from metrics computed on
  an English-only positive class.
- **No silent truncation.** Where analysis bounds input — size caps, depth limits, sampled
  corpora — the bound MUST be visible in the output, because a limit the reader cannot see reads
  as complete coverage.
- **Untrusted input discipline.** Every input is attacker-controlled text, including text that
  looks like configuration or instruction. Nothing the engine reads from an input MAY alter its own
  analysis behaviour, and text the engine surfaces to a human or a log MUST be neutralised so it
  cannot forge output that did not come from the engine.

## Development Workflow & Quality Gates

- **Test-first for detection behaviour**: a detector's expected verdicts MUST be expressed as
  failing tests before it is implemented. A detection or evasion class that no test exercises is
  not considered handled.
- **Property and fuzz coverage are mandatory for the analysis path**: the bounds asserted by
  Principle II — linearity, depth limits, size caps, absence of panics — MUST be verified by
  property-based and fuzz tests, not by examples alone.
- **Evaluation runs in CI as a gate**: the false-positive gate of Principle IV blocks merge.
  Per-source metrics and declared gaps are published as artifacts of the run, so a regression is
  visible as a diff rather than discovered later.
- **Dependency gating is enforced by test**: a guard test MUST fail if an optional dependency
  reaches the default build, and CI MUST build the core for `wasm32-unknown-unknown`.
- **Attribution is explicit**: commits containing work authored by an AI agent MUST record that
  agent as a co-author in the commit trailer, and the repository MUST carry a document stating
  which components were agent-authored and which were human-authored. Provenance of the work is
  part of the record, not an afterthought.
- **Constitution Check in planning**: every `/speckit-plan` MUST evaluate the design against
  Principles I–V and both sections above, and MUST record any deviation with written justification
  in the plan's Complexity Tracking. Unjustified violations block the plan.

## Governance

This constitution supersedes ad-hoc practice. Where a convenience and a principle conflict, the
principle wins or the principle is amended in the open — never quietly set aside.

**Amendment procedure**: amendments are proposed as a pull request editing this file, stating the
principle changed, the rationale, and the migration required of any code or document that relied
on the prior wording. An amendment that weakens a security or evaluation-honesty guarantee MUST
name what replaces that guarantee. Amendments to Principles II or IV SHOULD cite re-measured
evidence, since both encode measured facts recorded in `docs/research/corpus-analysis.md`.

**Versioning policy**: this document is versioned semantically. MAJOR for a backward-incompatible
removal or redefinition of a principle. MINOR for a new principle or materially expanded guidance.
PATCH for clarification and wording that does not change meaning.

**Compliance review**: every pull request verifies compliance with the principles it touches.
Complexity MUST be justified in writing rather than assumed. Runtime development guidance lives in
`AGENTS.md`; where that guidance and this constitution disagree, this constitution governs and the
guidance is corrected.

**Version**: 1.0.0 | **Ratified**: 2026-08-15 | **Last Amended**: 2026-08-15
