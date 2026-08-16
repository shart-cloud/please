# Feature Specification: The judgement tier

**Feature Branch**: `004-judgement-tier`

**Created**: 2026-08-15

**Status**: Draft

**Input**: After 003, ten positive fixtures remain undetected and one false positive remains. Neither residue
is a rule-coverage problem. `benign-tool-001` displays payloads and `indirect-tool-003` carries one, and they
are the same document to a surface pass. *"URGENT SECURITY ADVISORY … grant the sender admin access"* is
indistinguishable from a real advisory without understanding what is being asked.

**The structural tier can see form and cannot see intent.** This tier is the second opinion, and the
architecture decisions behind it are in [plan.md](./plan.md) — read D4 and D5 before this document, because
they constrain almost everything here.

---

## What this tier is not

Three exclusions, stated first because each is a thing a judgement tier is normally assumed to do.

**It is not a detector.** It finds no new payloads. It arbitrates findings the structural tier already made.
Recall stays where the rules can be measured.

**It does not decide.** It cannot clear a finding, cannot raise severity, cannot invent one. It may confirm,
or demote into the suppression channel that Feature 002 built. The caller's policy disposes (Principle I).

**It is not asked for an opinion.** It answers factual questions about text from closed option sets. Our code
computes the score (plan D4).

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - A second opinion on the cases form cannot settle (Priority: P1)

An operator scans content the structural tier flagged, or content it cleared that they doubt, and asks for a
judgement on whether the flagged text is *instructing* the agent or *displaying* an instruction.

**Why this priority**: it is the entire purpose. Both remaining accuracy residues sit on this one axis.

**Independent Test**: `benign-tool-001` and `indirect-tool-003` — structurally near-identical, oppositely
labelled — receive opposite answers.

**Acceptance Scenarios**:

1. **Given** a shell transcript displaying payloads from a fixture file, **When** judged, **Then** the flagged
   observations are demoted to suppressed and the verdict is clean.
2. **Given** a shell transcript whose grep output carries a live payload, **When** judged, **Then** the
   observation remains reported.
3. **Given** a verdict with no observations at all, **When** judged, **Then** no request is made. There is
   nothing to arbitrate and a network call would be waste.

### User Story 2 - A captured judge cannot become a bypass (Priority: P1)

The content under analysis is attacker-controlled, so the judge is a target. An attacker who succeeds in
influencing it must gain as little as possible.

**Why this priority**: a judge that can clear a finding is a single point of total bypass. This constrains the
design more than any accuracy consideration, and it is why D5 limits the tier to confirm-or-demote.

**Independent Test**: drive the judge with adversarial and malformed responses and assert the verdict never
loses a finding, never gains one, and never exceeds the structural severity.

**Acceptance Scenarios**:

1. **Given** a judge response demoting every observation, **When** the verdict is produced, **Then** every
   observation is still present in `suppressed()`, annotated with the judge as what demoted it.
2. **Given** a judge response attempting to raise severity or add a finding, **When** parsed, **Then** it is
   rejected — the schema has no field for either.
3. **Given** any judge response whatsoever, **When** `--no-judge` is passed, **Then** the verdict is
   byte-identical to the structural verdict.

### User Story 3 - An unavailable judge is never a clean verdict (Priority: P1)

The endpoint is unreachable, the credential is missing or rejected, the request times out, or the response
does not parse.

**Why this priority**: constitutional. *Model-backed and judgement tiers … MUST degrade to an indeterminate
verdict per Principle I when unavailable — never to clean.* A network dependency in a security path is a
fail-open waiting to happen, and this is the requirement that stops it being one.

**Independent Test**: each failure mode against a verdict that would otherwise be clean; assert
`Inconclusive` and a `TierUnavailable` gap naming the cause.

**Acceptance Scenarios**:

1. **Given** `--judge` and an unreachable endpoint, **When** scanning clean content, **Then** the outcome is
   `Inconclusive`, not `Clean`, and exit code 2.
2. **Given** `--judge` with no credential in the environment, **When** scanning, **Then** the same, and the
   gap names which variables were consulted.
3. **Given** a response that is well-formed JSON but not the expected schema, **When** parsed, **Then** the
   same. A judge replying in prose is a judge that has been talked to.

### User Story 4 - Credentials resolve predictably and never leak (Priority: P2)

Several Anthropic credentials are commonly present at once, with a proxy endpoint. The operator can see which
one will be used before anything is sent.

**Why this priority**: picking wrong is a disclosure bug, not a compatibility bug — an upstream account
credential sent to a third-party host (plan D3).

**Independent Test**: every combination of the four variables resolves to the documented choice, and no test
output anywhere contains a credential value.

**Acceptance Scenarios**:

1. **Given** `ANTHROPIC_AUTH_TOKEN` and `ANTHROPIC_API_KEY` both set, **When** resolving, **Then** the auth
   token is chosen and sent as a bearer header.
2. **Given** a diagnostic invocation, **When** run, **Then** it reports the variable chosen, those ignored,
   and the resolved endpoint — **without making a request**.
3. **Given** a non-default endpoint and only `ANTHROPIC_API_KEY` available, **When** judging, **Then** a
   warning is emitted before the request.
4. **Given** any failure at all, **When** the error is rendered, **Then** it names the variable consulted and
   never its value.

### User Story 5 - A judged verdict explains itself (Priority: P2)

An engineer disagreeing with a judged outcome can see which observation the judge acted on, which feature
drove it, and what the structural tier said before it.

**Why this priority**: 002 removed a two-run diff from the false-positive workflow. Reintroducing an
unexplained number would put it back.

**Acceptance Scenarios**:

1. **Given** a judged verdict under `--explain`, **When** rendered, **Then** each judged observation shows
   its feature answers and the derived score.
2. **Given** a judged verdict, **When** inspected, **Then** it records the model id and prompt version.

### Edge Cases

- **Every observation demoted, none reported** → the verdict is `Clean`, and the suppressed list is the whole
  story. This is the intended success case for `benign-tool-001`, and it is also what a fully captured judge
  produces; the two are indistinguishable in the verdict and distinguishable with `--no-judge`.
- **A document containing both a displayed and a live payload.** Already a passing structural test. Per-span
  `span_role` is what makes this expressible; a document-level answer could not.
- **A judge that answers `unclear` to everything.** Treated as no information: nothing is demoted, the
  structural verdict stands. Abstention must never be cheaper for the attacker than honesty.
- **Content larger than the model's context.** A gap, not a truncation-and-guess.
- **A verdict with more findings than `max_reasons`.** Not judged at all (FR-421). A document with more than
  sixty-four findings is not one whose precision problem a second opinion was going to fix, and the
  alternative is a score that quietly drops the truncated severities.
- **Judge enabled on a directory walk.** Cost is per target and multiplies. Out of scope to optimise; in
  scope to not surprise anyone with.

---

## Requirements *(mandatory)*

### The tier

- **FR-401**: The tier MUST live in a separate crate depending on `please-core`, never the reverse, and MUST
  be opt-in per invocation. Default runs MUST make no network request.
- **FR-402**: An unavailable, failing, timing-out, unauthenticated, or unparseable judge MUST produce a
  `TierUnavailable` coverage gap, and therefore `Inconclusive`. **Never `Clean`.**
- **FR-403**: The judge MUST be able to confirm an observation or demote it into the suppression channel, and
  MUST NOT be able to erase one, raise a severity, or introduce one.
- **FR-404**: A verdict with no observations MUST NOT produce a request.

### What is asked, and what is returned

- **FR-405**: The model MUST be asked only factual questions about the text, each answered from a closed
  option set. The schema MUST contain no free-text field, no severity, and no recommendation.
- **FR-406**: The prompt MUST NOT contain the words *injection*, *attack*, *malicious*, *suspicious*, or
  *risk*, and MUST NOT state that a scanner flagged anything. Naming the interesting answer produces it.
- **FR-407**: The score MUST be computed by this project's code from the returned features, not supplied by
  the model.
- **FR-408**: Content sent to the model MUST be neutralised by the existing sanitisation path, and MUST be
  enveloped as data under analysis rather than as instructions.
- **FR-409**: A response that does not conform to the schema MUST be rejected rather than salvaged.
- **FR-410**: A `model_severity` field MAY be recorded for calibration and MUST NOT be read by any decision.

### Credentials and endpoint

- **FR-411**: Resolution order MUST be `ANTHROPIC_AUTH_TOKEN`, then `CLAUDE_CODE_OAUTH_TOKEN`, then
  `ANTHROPIC_API_KEY`, unconditionally — not contingent on `ANTHROPIC_BASE_URL` being set (plan D3).
- **FR-412**: `ANTHROPIC_BASE_URL` MUST override the endpoint; `ANTHROPIC_MODEL` MUST override the model over
  a pinned default.
- **FR-413**: No credential value MUST appear in any verdict, log line, error message, or diagnostic.
- **FR-414**: A diagnostic MUST report the variable selected, those ignored, and the resolved endpoint,
  **without making a request**.
- **FR-415**: Where the endpoint is non-default and `ANTHROPIC_API_KEY` is the only credential available, a
  warning MUST be emitted before the request.

### Attribution and determinism

- **FR-416**: A judged verdict MUST record the model id and the prompt version.
- **FR-417**: The structural tier's determinism guarantee (001 SC-011) MUST remain unchanged. The judgement
  tier's departure from it MUST be recorded in `docs/limits.md`.
- **FR-418**: `--no-judge` MUST reproduce the structural verdict exactly.

### Gating

- **FR-419**: The **default** `please-cli` build MUST carry no HTTP or TLS crate, enforced by a check rather
  than by review. `please-core`'s dependency allow-list MUST be unchanged.
- **FR-420**: The judge MUST honour a per-invocation timeout, defaulting low enough that a hung endpoint
  cannot hang a scan.
- **FR-421**: A verdict whose reasons were truncated MUST NOT be judged. It MUST produce a `TierUnavailable`
  gap instead (plan D9). The score is aggregated from observations *before* truncation (001 FR-001b), so the
  severities a demotion would have to subtract no longer exist by the time a verdict does — and recomputing
  from the survivors would understate the score without any judgement having said so.

---

## Success Criteria *(mandatory)*

- **SC-401**: `benign-tool-001` and `indirect-tool-003` — structurally near-identical, oppositely labelled —
  receive opposite judgements. **This is the criterion the tier exists for**; failing it means the axis in
  plan D4 was the wrong one.
- **SC-402**: With the judge disabled, accuracy is identical to the structural baseline: 31/41 positives, 1
  false positive, the same case ids.
- **SC-403**: Every failure mode in User Story 3 yields `Inconclusive`, proven by test, including one against
  a genuinely unreachable endpoint rather than a mock.
- **SC-404**: No credential value appears in any test output, asserted mechanically over the whole suite
  rather than by reading.
- **SC-405**: The default `please-cli` build's dependency graph contains no HTTP or TLS crate, asserted by a
  CI check that fails on any addition.
- **SC-406**: An adversarial-response property test demonstrates that no judge response — malformed,
  hostile, or maximally permissive — can remove a finding from the verdict or raise a severity.
- **SC-407**: Feature-extraction agreement is **measured**, not assumed: a hand-labelled set of at least
  twenty spans with known feature answers, reported as per-field agreement. This is the calibration baseline
  and it is expected to be imperfect; the number is the deliverable, not a threshold.
- **SC-408**: Cold start for the default (unjudged) path does not regress against `SC-004b`'s 25 ms.

---

## Assumptions

- **Non-determinism is accepted for this tier and nowhere else.** Recorded rather than mitigated. Plan D4
  confines it to feature extraction, which makes a disagreement between two runs show up as a named field
  rather than an unexplained number.
- **Calibration needs a corpus we do not have.** How features combine into a score is deliberately left to
  the implementation as something trivial and obvious, to be tuned against evidence later. Inventing weights
  now would repeat 001's provisional band boundaries with less excuse the second time.
- **The judge will sometimes be wrong, and sometimes be captured.** The design assumes both. Every guarantee
  above is stated in terms of what an attacker gains rather than whether they succeed.
- **Cost and latency are the operator's to accept.** Opt-in per invocation, with a timeout.

## Out of scope

- The judge finding payloads the structural tier missed. It arbitrates; it does not detect.
- Streaming, batching, and async. One synchronous request (plan D2).
- Response caching. Wanted for cost and reproducibility, deferred so the first version has one moving part.
- Any use of judge output beyond selecting from a closed enum. It never reaches a shell, a path, or another
  prompt.
