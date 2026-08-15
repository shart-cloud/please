# Feature Specification: Structural Detection & Scan CLI

**Feature Branch**: `001-structural-detection-cli` (branch creation deferred — repository not yet
initialised)

**Created**: 2026-08-15

**Status**: Draft

**Input**: First deliverable slice of PLEASE (Prompt-Layer Evaluation And Security Engine): the
verdict model, the structural detection tier, and the scan command that exposes both. Scoped from
the corpus findings in `docs/research/corpus-analysis.md` and governed by
`.specify/memory/constitution.md` v1.0.0.

## Clarifications

### Session 2026-08-15

- Q: When several rules fire on one input, how should their individual severities combine into the
  single verdict score? → A: Highest single severity, plus a small capped bonus per additional
  distinct detection class present (FR-001a). Summing was rejected because score would then grow with
  input length, failing long benign documents for their size alone; pure maximum was rejected because
  it discards genuine multi-class corroboration. Counting distinct classes (at most six) rather than
  matches (unbounded) captures corroboration without length sensitivity.
- Q: Where should the one-million-input fuzzing campaign actually run, given that a per-change job
  cannot afford it? → A: A scheduled campaign accumulating toward and past 1M inputs, recording
  iteration count and crashes as run artifacts, with a short bounded smoke on every change (SC-006).
  Self-hosted capacity is available; which organisation hosts the runners is deferred and non-blocking.
- Q: SC-001 asks that a reviewer can state what was found within two minutes, which no automated
  check can verify — how should it be handled? → A: Split it. Output completeness becomes a mechanical
  per-change gate (SC-001); human comprehension becomes a once-per-release recorded walkthrough with a
  named reader who did not build the tool (SC-001a). One criterion was carrying two claims, only one
  of which a machine can settle.
- Q: How should the requirement that the tool never touches the network actually be verified? → A: A
  static gate banning networking and filesystem interfaces in the engine's own sources, plus the
  dependency allow-list (FR-031). The allow-list alone cannot prove it, since reaching the network
  needs no dependency. Runtime verification under network isolation is optional defence in depth and
  may be added later on self-hosted capacity.
- Q: When scanning a directory, what should happen if one file among many cannot be read? → A: That
  target gets an inconclusive verdict with a machine-readable cause and the walk continues; the summary
  uses the same precedence as a single verdict; usage error is reserved for invocation faults
  (FR-032a, FR-032b). Resolves a three-way conflict between FR-026, FR-028, and FR-032 — an unreadable
  file is incomplete analysis, not an invocation mistake.
- Decision (from analysis review): the score is aggregated over all matches **before** reason-count
  truncation, since reasons are ordered by location rather than severity and truncating first could
  discard the highest-severity finding (FR-001b).
- Decision (from analysis review): SC-003's 1% false-positive rate is qualified by a minimum
  hard-negative set of 200 examples, measured at the default threshold. Without a stated denominator
  the constitution's mandated false-positive gate is not implementable — 1% over fewer than 100
  negatives silently means zero.
- Decision (from analysis review): FR-028 now enumerates all six status codes, matching the command
  contract. Previously the contract defined six while the requirement authorised four, so the
  below-threshold and split-error codes were unspecified.
- Decision (from analysis review): FR-020 restated in testable form — rule-like or configuration-like
  content must yield the same verdict as inert prose, and per-input verdicts must be independent of
  scan order. It was previously a security MUST that no test could exercise.

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Check an artifact before trusting it (Priority: P1)

A developer has been handed a skill file, an agent instruction document, a downloaded prompt
template, or a pasted block of text, and wants to know whether it contains instructions aimed at
the agent that will read it rather than at the human reviewing it. They run a scan against the file
and get back a plain answer: a risk level, and a list of specific reasons naming what was found and
where in the text it sits.

**Why this priority**: This is the smallest thing that delivers value on its own. A reviewer with no
integration work and no configuration can point the tool at a file and learn something they could
not easily see by reading it — because the most effective payloads are the ones invisible to a
reader. Every later story reuses this same judgement path.

**Independent Test**: Fully testable by scanning a set of committed fixture files — one per
detection class, plus benign controls — and asserting the reported risk level and reasons. Delivers
value with no harness, no configuration, and no network.

**Acceptance Scenarios**:

1. **Given** a document containing an instruction-override phrase directed at an agent, **When** the
   developer scans it, **Then** a non-clean risk level is reported, with at least one reason naming
   the detection class and the location of the matching text.
2. **Given** a document containing text hidden with invisible or direction-altering characters,
   **When** the developer scans it, **Then** the hidden content is reported as a reason, and the
   reported location identifies where the hidden characters occur.
3. **Given** a document containing an encoded payload that decodes to an instruction-override
   phrase, **When** the developer scans it, **Then** the payload is reported, and the reason states
   both the encoding recognised and the decoded content that triggered it.
4. **Given** an ordinary technical document that discusses prompt injection as its subject matter,
   **When** the developer scans it, **Then** a clean verdict is reported.
5. **Given** any scanned input, **When** the verdict is displayed, **Then** any quoted excerpt from
   the input is rendered so that it cannot alter or forge the surrounding output.

---

### User Story 2 - Gate an agent's tool call automatically (Priority: P2)

An agent harness or a coding agent's pre-tool hook needs to consult the scanner on every piece of
untrusted text before the agent acts on it — a file it just read, a tool result, a fetched page, the
description of a tool offered by a remote server. The integration is non-interactive: it invokes the
scan, reads a machine-readable result and a status code, and applies its own policy to decide
whether to proceed, warn, or refuse.

**Why this priority**: This is the product's actual purpose and its main distribution path — it is
how the engine reaches agents that are not written in the same language. It ranks second only
because it depends on the judgement path from Story 1 already existing and being trustworthy.

**Independent Test**: Testable by invoking the scan non-interactively against fixtures and asserting
the exact status code and the structure of the machine-readable output, with no human reading the
result. A sample hook script exercising the contract demonstrates it end to end.

**Acceptance Scenarios**:

1. **Given** untrusted text supplied on standard input, **When** the scan is invoked
   non-interactively, **Then** a machine-readable result is written to standard output and nothing
   that is not part of that result is mixed into it.
2. **Given** a clean input, **When** the scan completes, **Then** the status code indicates "no
   action required" and is distinct from every other outcome.
3. **Given** an input whose risk reaches the configured threshold, **When** the scan completes,
   **Then** the status code indicates "risk found" and is distinct from both the clean and the
   error outcomes.
4. **Given** an invalid invocation or an unreadable target, **When** the scan is attempted, **Then**
   the status code indicates an operational error, distinguishable from "risk found", and the
   diagnostic is written separately from the result stream.
5. **Given** the same input and the same rule set, **When** the scan is repeated, **Then** the
   result is identical, so a caller can cache and diff results.
6. **Given** a directory containing a mix of clean and risk-bearing files, **When** it is scanned,
   **Then** a per-target verdict is reported for each file and a single summary status is returned
   that reflects the highest risk found among them.
7. **Given** a directory in which one file cannot be read and all others are clean, **When** it is
   scanned, **Then** the unreadable file reports an inconclusive verdict with a machine-readable
   cause, every other file reports its own verdict, and the summary status is inconclusive rather
   than clean.

---

### User Story 3 - Hostile and oversized input is handled honestly (Priority: P3)

A caller runs the scanner in the path of every tool call, which means an attacker who controls the
scanned text also controls the scanner's workload. That caller needs two guarantees: the scan cannot
be made slow or unstable by crafted input, and when the scan genuinely cannot reach a conclusion it
says so rather than reporting the input clean.

**Why this priority**: Both guarantees are security-critical, and the second is the difference
between a firewall that fails visibly and one that fails open. It ranks third only because it is
demonstrated against the judgement path and contract that Stories 1 and 2 establish.

**Independent Test**: Testable by driving the scan with adversarial inputs — inputs at and beyond
the size cap, deeply nested encodings, pathological repetition, malformed and truncated encodings,
invalid text encodings — and asserting bounded completion time, absence of crashes, and an explicit
inconclusive outcome wherever analysis was cut short.

**Acceptance Scenarios**:

1. **Given** an input larger than the configured maximum, **When** it is scanned, **Then** an
   explicit inconclusive outcome is reported naming the size limit as the cause, and it is never
   reported as clean.
2. **Given** an input whose encoded content is nested deeper than the configured decode limit,
   **When** it is scanned, **Then** the layers analysed are reported and the unexamined remainder is
   reported as inconclusive.
3. **Given** any input at all, including malformed, truncated, or non-text content, **When** it is
   scanned, **Then** the scan completes without crashing and within a time bound proportional to
   the input's length.
4. **Given** a rule set that fails to load, **When** a scan is attempted, **Then** the outcome is an
   explicit failure or inconclusive result, and never a clean verdict produced by an empty rule set.
5. **Given** an input that produces an inconclusive outcome, **When** the caller inspects the
   result, **Then** the reason for inconclusiveness is machine-readable, so the caller's policy can
   distinguish it from both clean and flagged.

---

### User Story 4 - Tune and extend detection without a rebuild (Priority: P4)

A team adopting the scanner finds that one rule fires on a pattern common in their own documents,
and separately wants to add a rule for a payload style they have seen in the wild. They edit
declarative rule definitions, point the scan at them, and see the change take effect — and every
verdict states which rule set version produced it, so a result from last week can be explained.

**Why this priority**: It is what makes the tool survive contact with a real codebase instead of
being disabled at the first false positive, and it is required by the governing principle that rules
are reviewable data. It ranks last because the built-in rule set delivers value before any of it is
customisable.

**Independent Test**: Testable by scanning one fixture against two rule sets that differ in a single
rule and asserting the verdicts differ accordingly, and by asserting the rule set identity recorded
in each verdict.

**Acceptance Scenarios**:

1. **Given** a rule definition added to a rule set, **When** a matching input is scanned, **Then**
   the new rule appears as a reason in the verdict, with no rebuild of the tool.
2. **Given** a built-in rule the team wishes to suppress, **When** it is disabled in their rule set,
   **Then** inputs that previously matched only that rule report clean.
3. **Given** any completed scan, **When** the verdict is inspected, **Then** it identifies the rule
   set version and the engine version that produced it.
4. **Given** a rule set containing a malformed rule, **When** it is loaded, **Then** loading fails
   with a diagnostic identifying the offending rule, rather than silently skipping it.

---

### Edge Cases

- An input that is entirely benign but happens to contain an encoded string that decodes to
  meaningless bytes — must not be reported as an encoded payload.
- A document whose subject matter *is* prompt injection: a threat model, an advisory, a rule
  definition, or this specification. Must report clean. This is the highest-value false-positive
  class to get right, because these documents circulate among exactly the people who would
  otherwise adopt the tool.
- Text mixing several scripts or using characters that resemble Latin letters, where the resemblance
  is legitimate (ordinary non-English prose) rather than an evasion attempt.
- An input containing an instruction-override phrase inside quoted example text, where the
  surrounding document is explaining the phrase rather than issuing it.
- Zero-length input, whitespace-only input, and input consisting of a single very long line with no
  breaks.
- An input that decodes to itself, or two layers that decode into each other, forming a cycle.
- Content whose declared form and actual form disagree — a file named as one type containing
  another.
- Simultaneous matches from many rules on one input: the reported reasons must remain bounded rather
  than growing to the size of the input.
- An input arriving through a stream that ends unexpectedly mid-way.
- A directory scan in which one file cannot be read — because of permissions, a broken link, or a
  concurrent deletion — while hundreds of others can. The unreadable file must neither abort the scan
  nor vanish from the result, since a file that was never examined must not be absorbed into a clean
  summary.
- A directory containing no scannable targets at all, and a directory scanned while its contents are
  changing underneath the walk.

## Requirements *(mandatory)*

### Functional Requirements

**Verdict model**

- **FR-001**: The system MUST produce, for every completed scan, a verdict comprising a risk level,
  a numeric score on a documented fixed scale, and an ordered list of reasons.
- **FR-001a**: The score MUST be aggregated as the highest single reason severity, plus a bounded
  bonus for each additional **distinct detection class** present beyond the highest-scoring one, with
  both the per-class bonus and the total bonus capped, and the final score capped at the scale
  maximum. Aggregation MUST NOT be sensitive to the number of matches or to input length: a benign
  document MUST NOT accrue risk merely by being long or by repeating an innocuous match.
- **FR-001b**: The score MUST be computed over every match found, **before** any reason-count bound
  truncates the reported list. Because reasons are ordered by location rather than by severity,
  truncating first could discard the highest-severity finding and understate the score.
- **FR-002**: Each reason MUST identify the rule that produced it, the detection class it belongs
  to, and the location within the input where the matching content occurs.
- **FR-003**: The verdict MUST distinguish three mutually exclusive outcomes: clean, risk found, and
  inconclusive. An inconclusive outcome MUST carry a machine-readable cause.
- **FR-004**: The system MUST NOT report a clean verdict for any input whose analysis did not
  complete, for any reason.
- **FR-005**: Every verdict MUST record the identity and version of the rule set and of the engine
  that produced it.
- **FR-006**: The system MUST NOT decide on the caller's behalf whether a verdict permits an action.
  It reports; the caller's configured policy disposes.
- **FR-007**: The number of reasons in a verdict MUST be bounded independently of input length, and
  when reasons are omitted because of that bound, the verdict MUST state that omission.

**Detection capability (structural tier)**

- **FR-008**: The system MUST detect instructions directed at a reading agent that attempt to
  override, replace, or supersede its prior instructions.
- **FR-009**: The system MUST detect text concealed from a human reader by invisible, zero-width,
  direction-altering, or non-printing characters, and MUST report the concealed content it
  recovered.
- **FR-010**: The system MUST detect characters chosen to resemble other characters where the
  resemblance is used to evade textual matching, without flagging legitimate non-English text.
- **FR-011**: The system MUST recognise encoded and transformed content, decode it within a bounded
  depth, re-analyse what it recovers, and report both the transformation recognised and the
  triggering decoded content. The transformations covered MUST include, at minimum: base-64
  encoding, hexadecimal encoding, rotation ciphers, character-reversal, and glyph-substitution
  spelling ("leetspeak") — the five families that are explicitly labelled in the evaluation corpus
  and therefore independently measurable.
- **FR-012**: The system MUST detect attempts to forge conversational or structural boundaries —
  text impersonating a system instruction, a role marker, a tool result, or a delimiter that would
  cause data to be read as instruction.
- **FR-013**: The system MUST detect solicitations for an agent's own configuration, instructions,
  or credentials.
- **FR-014**: The system MUST distinguish content that issues an instruction from content that
  describes or quotes one, and MUST treat the latter as benign.
- **FR-015**: Each detection class MUST be independently addressable, so that it can be reported on,
  scored, and disabled in isolation.

**Bounds and safety**

- **FR-016**: The system MUST complete analysis in time proportional to input length, with no
  input causing superlinear cost.
- **FR-017**: The system MUST enforce a configurable maximum input size, with a documented default,
  and MUST report an inconclusive outcome naming that cause for inputs exceeding it.
- **FR-018**: The system MUST enforce a configurable maximum decoding depth with a documented
  default, and MUST report what it did not examine.
- **FR-019**: The system MUST terminate on every input without crashing, hanging, or consuming
  unbounded memory, including malformed, truncated, cyclic, and non-textual input.
- **FR-020**: The system MUST NOT allow content within a scanned input to alter how that input, or
  any subsequent input, is analysed. Specifically, and testably: (a) an input containing text that
  resembles a rule definition, a configuration directive, or an instruction addressed to the scanner
  MUST produce the same verdict as an otherwise identical input in which that text is inert prose;
  and (b) scanning a set of inputs MUST produce the same verdict for each input regardless of the
  order in which they were scanned, or of what was scanned before them.
- **FR-021**: Any excerpt of scanned input reproduced in output intended for a human or a log MUST
  be neutralised so that it cannot forge, erase, or reorder surrounding output.

**Rules as data**

- **FR-022**: Detection rules MUST be expressed as declarative, human-readable definitions that are
  reviewable without executing them.
- **FR-023**: The system MUST load rule sets at run time, and MUST allow a caller to supply
  additional rules and to disable built-in rules.
- **FR-024**: The system MUST reject a malformed **or resource-exhausting** rule set with a diagnostic
  identifying the offending rule, and MUST NOT proceed with a partially loaded rule set. A rule set MUST NOT
  yield an executable scanning capability unless every caller-supplied rule has been proven to compile within
  a stated resource budget.
  > **Amended by feature 002 (FR-150).** As originally written this covered only *malformed* rule sets, and a
  > resource-exhausting rule is not malformed: `a{1000}{1000}{1000}` is nineteen bytes of valid
  > regular-expression syntax that `regex_syntax` accepts in microseconds and that compiles to an automaton
  > with on the order of 10⁹ states. The implementation had the check — `Ruleset::validate_compiled` — but as
  > a separate public call nothing invoked, so a requirement about malformedness described neither the threat
  > nor the code. The second sentence is the part that had no requirement behind it.
- **FR-025**: The system MUST ship a default rule set that requires no configuration to be useful.

**Scan command**

- **FR-026**: Users MUST be able to scan content supplied as a file path, as a directory to be
  walked, or on standard input.
- **FR-027**: The command MUST offer both a human-readable presentation and a machine-readable
  result, with the machine-readable form written cleanly to the result stream and diagnostics
  written separately.
- **FR-028**: The command MUST return six distinct, documented, stable status codes: clean; risk found
  at or above the active threshold; risk found **below** the active threshold; inconclusive; usage
  error; and internal error. Below-threshold findings MUST be distinguishable from clean so that a
  caller wanting to allow-but-log can tell "nothing found" from "something found, under your bar".
  Usage and internal errors MUST be distinguishable from every risk outcome, so that a caller cannot
  mistake a failed invocation for a safe input.
- **FR-029**: The threshold at which a scan reports risk found MUST be configurable, with a
  documented default.
- **FR-030**: Repeated scans of identical input under an identical rule set MUST produce identical
  results.
- **FR-031**: The command MUST NOT perform network access, and MUST NOT require any downloaded
  resource in order to return a verdict. This MUST be enforced mechanically by two complementary
  checks: a static gate rejecting networking and filesystem interfaces within the detection engine's
  own sources, and the dependency allow-list covering what that gate cannot see. The allow-list alone
  is insufficient, because reaching the network requires no dependency at all. Runtime verification
  under network isolation MAY be added as defence in depth.
- **FR-032**: When scanning a directory, the command MUST report per-target verdicts and MUST report
  a summary status derived from them by a documented rule.
- **FR-032a**: A target that cannot be read MUST receive an inconclusive verdict carrying a
  machine-readable cause, and the walk MUST continue. Such a target MUST NOT abort the scan and MUST
  NOT be silently skipped: an unscanned file absorbed into a clean summary is the same fail-open that
  FR-004 forbids, reproduced at directory scope. Usage error is reserved for invocation faults, such
  as a root path that does not exist.
- **FR-032b**: The summary status MUST be derived by the same precedence the single-target verdict
  uses — risk found outranks inconclusive, which outranks clean — so that a directory containing any
  unreadable or unanalysable file never summarises as clean.

### Key Entities

- **Scan target**: a unit of untrusted text submitted for analysis, together with its origin (a file
  path, a stream, or a labelled caller-supplied buffer). Origin is metadata for reporting; it never
  influences judgement.
- **Verdict**: the outcome of one completed scan — outcome kind (clean, risk found, inconclusive),
  risk level, score, ordered reasons, any inconclusiveness cause, and the rule set and engine
  identity that produced it.
- **Reason**: one supporting observation within a verdict — the rule that fired, its detection
  class, the location in the input, the recovered or matched content, and, where the match came from
  decoded content, the chain of transformations that reached it.
- **Detection class**: a named family of related payload techniques (instruction override,
  concealment, character confusion, encoding, boundary forgery, configuration solicitation).
  Independently reportable and independently disableable.
- **Rule**: one declarative detection definition — identity, detection class, matching criteria,
  severity contribution, and provenance. The unit a reviewer reads and a team overrides.
- **Rule set**: a versioned, identified collection of rules, resolved from the built-in default plus
  any caller-supplied additions and suppressions.
- **Scan policy**: the caller-owned configuration governing thresholds, size and depth limits, and
  which detection classes are active. Owned by the caller, never inferred from scanned content.

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-001**: Every risk-found verdict presents, without a lookup, the identity of the rule that
  fired, its detection class, the location in the input, a neutralised excerpt, and a description of
  what the rule detects. This is checked mechanically on every change.
- **SC-001a**: Once per release, a reader not involved in building the tool scans a prepared suspicious
  file and correctly states what was found and where, using only the tool's output, within two
  minutes. This is a recorded manual check with a named reader and a date, not an automated gate —
  the comprehension it measures is what decides whether a person trusts a finding enough to act on it,
  and no automated check can stand in for it.
- **SC-002**: For every detection class, a curated fixture set is detected at 100% and its paired
  benign controls produce no findings.
- **SC-003**: On a curated hard-negative set of **at least 200 examples** that includes technical
  security prose — threat models, advisories, and documents whose subject is prompt injection — the
  false-positive rate is at most 1%, measured at the default threshold. The minimum set size is part
  of the criterion: a rate of 1% over fewer than 100 negatives silently means zero, which is a
  materially different and stricter bar than the one intended.
- **SC-004a** (warm, per scan): 95% of scans of inputs up to 4 KB return a verdict within 10 milliseconds,
  and sustained throughput is at least 10 MB per second, both measured on a single core of commodity hardware,
  with the engine already constructed.
- **SC-004b** (cold start): process launch to first verdict, including rule-set preparation, completes within
  25 milliseconds for the built-in rule set.
  > **Amended by feature 002 (FR-151).** One criterion covering both was unfalsifiable in a useful way,
  > because the two have different causes and different remedies. A warm scan is bounded by the matching
  > engine and the match cap; cold start is bounded by how many patterns get compiled before the first
  > verdict, which is why the built-in set is validated in CI and compiled lazily while caller-supplied rules
  > are compiled once at preparation and retained. Measured at 002's Phase 3 checkpoint: preparing the
  > built-in set costs ~489 µs and compiles nothing, against ~5.75 ms if every pattern is compiled. Merging
  > the two numbers would have hidden the entire reason preparation is asymmetric.
- **SC-005**: Measured cost grows no faster than linearly with input length across four orders of
  magnitude of input size.
- **SC-006**: Fuzzing of at least one million generated inputs produces no crash, no hang, and no
  unbounded memory growth. The count is cumulative across a **scheduled** campaign whose iteration
  total and any discovered crashes are recorded as artifacts of the run; each individual change is
  additionally covered by a short bounded fuzz smoke that must find no crash. A criterion with no
  scheduled home would be decorative, so the schedule is part of the criterion.
- **SC-007**: 100% of inputs whose analysis is cut short report an inconclusive outcome with a
  machine-readable cause, and 0% report clean.
- **SC-008**: 100% of risk-found verdicts name at least one rule and one location, so every finding
  is diagnosable without re-running the tool.
- **SC-009**: An integrator can wire the scan into an agent's pre-action hook and have it gate on
  the result using only the documented status codes and machine-readable output, without reading the
  tool's source.
- **SC-010**: A team can suppress one built-in rule and add one rule of their own, and observe both
  changes take effect, without rebuilding or reinstalling the tool.
- **SC-011**: Identical input scanned under an identical rule set yields byte-identical
  machine-readable output across repeated runs and across host machines.
- **SC-012**: A verdict produced by an earlier version can be attributed to the exact rule set that
  produced it, using only the recorded verdict.

## Assumptions

- **Scope of this slice**: the verdict model, the structural detection tier, declarative rules, and
  the scan command. The classifier and judgement tiers, the browser-callable package and its
  published module, the harness-embedded hook integration, and the corpus-scale evaluation harness
  are each deferred to their own specifications.
- **Accuracy is verified here against curated fixtures, not the public corpus.** Corpus-scale,
  per-source stratified metrics and the false-positive gate described in the constitution require
  the evaluation harness and arrive with it. SC-002 and SC-003 are therefore stated against
  committed fixtures, which also avoids redistributing licence-restricted corpus text.
- **Harmful-content moderation is out of scope**, per the constitution: this feature judges whether
  text attacks the agent reading it, not whether its subject matter is objectionable.
- **Multilingual detection is a declared gap.** The available corpus contains no non-English attack
  examples, so no multilingual detection claim is made. Requirement FR-010 exists to prevent
  non-English text being *mistaken* for evasion, which is the failure that would actively harm
  non-English users.
- **The structural tier is pattern- and structure-based, not semantic.** It recognises payload form,
  not intent. Novel phrasings that no rule anticipates will pass, and closing that gap is the
  purpose of the later tiers. This limit is stated in the tool's own documentation rather than left
  for a user to discover.
- Scanned content is assumed hostile in all cases, including content that resembles configuration.
- The scheduled fuzzing campaign of SC-006 is assumed to run on self-hosted continuous-integration
  capacity, which is available. Which organisation hosts those runners is undecided and does not block
  the criterion; only the schedule and the recorded iteration count are load-bearing.
- Callers are assumed to own their own policy: this feature supplies thresholds and status codes,
  and takes no position on whether a given finding should block a given action.
- Scan targets are assumed to be text or to be treated as bytes; extracting text from container and
  document formats is out of scope for this slice.
- A default rule set is assumed to ship with the tool, so a first run requires no configuration.
- The three-outcome verdict model — clean, risk found, inconclusive — is assumed to be accepted by
  callers as a cost of not failing open. It follows directly from constitution Principle I.
