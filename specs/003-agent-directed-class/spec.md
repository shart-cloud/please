# Feature Specification: A detection class for content addressed to the agent

**Feature Branch**: `003-agent-directed-class`

**Created**: 2026-08-15

**Status**: Draft

**Input**: Analysis of the fourteen positive fixtures still undetected after Feature 002. Two of them carry a
signal no existing class describes: text that **speaks to the reading agent**. `NOTE TO AI ASSISTANT:` in CI
output; `NOTE TO PROCESSING AGENT:` inside an HTML comment in a skill file. Neither asks anything to be
disregarded, neither forges a role, neither solicits a secret — so none of the five classes fits, and both are
missed.

---

## Why this is a class rather than a rule

The bar was set by Feature 002, which **removed** a class for failing it. `Encoding` named a delivery
mechanism rather than a kind of finding, had no members no rule could declare, and caused a shipped defect.
Adding one back needs the same test applied in the same direction.

**Does it name a kind of finding?** Yes. "NOTE TO AI ASSISTANT:" is not how something arrived; it is what the
text is. It passes FR-130.

**Is it distinct from the five that exist?**

| Class | Would it cover an agent-addressed marker? |
|---|---|
| `Override` | No. "Fast-track this candidate" asks nothing to be disregarded |
| `Boundary` | No. Forging is a claim about **who is speaking**; addressing is a claim about **who is listening** |
| `Solicitation` | No. It asks for nothing belonging to the agent |
| `Concealment`, `Confusable` | No. Both are mechanisms |

The `Boundary` distinction is the one to be careful about, and it holds. A forged `SYSTEM:` marker claims the
authority of the platform. `NOTE TO AI:` claims nothing — it simply assumes the reader is a machine. Filing it
under `Boundary` would make that class's name stop describing its members, which is the `Encoding` mistake
run backwards.

**The underlying semantic, stated plainly.** In indirect injection the agent is supposed to be *processing*
content — summarising an email, reading a tool result, following a skill file. Content that **addresses** the
agent is anomalous by construction, because nothing in the legitimate workflow has any reason to talk to it.

**And the precision should be unusually good.** Every false positive this project has fought is security prose
*quoting* a payload. Prose about attacks quotes them constantly and addresses the agent never — a threat model
containing `NOTE TO AI ASSISTANT:` has it inside a quote or a fence, where existing suppression already
handles it. This class should therefore behave far better than `override`, which is the worst offender. That
is a prediction, and SC-303 exists to falsify it.

---

## Clarifications

### Session 2026-08-15

- **Q**: Should HTML comments be part of this feature? → **A**: No. They were handled separately and are
  already shipped: a comment is a concealing context that can never suppress, and a payload inside one emits
  a `Concealment` observation alongside. `indirect-skill-001` carries both signals; the comment half is done
  and the addressing half is this feature.
- **Q**: Should the class cover emphasis markers like `IMPORTANT:` followed by an imperative? → **A**: Not in
  this slice. Six of the fourteen remaining misses use `IMPORTANT:`, but so does most technical
  documentation, including this repository's. It is a corroborating signal at best and is deferred to
  FR-310.

---

## User Scenarios & Testing *(mandatory)*

### User Story 1 - Content that talks to the agent is reported (Priority: P1)

A tool result, skill file, or email contains text addressed to the reading agent rather than to the human the
document is for. The scanner reports it, and names why.

**Why this priority**: It is the only signal in the two affected fixtures, so nothing else can catch them. It
is also the highest-precision signal available — see the argument above.

**Independent Test**: Scan a document whose only anomaly is an agent-addressed marker and assert a finding of
the new class, with no other class firing.

**Acceptance Scenarios**:

1. **Given** CI output containing `NOTE TO AI ASSISTANT: <instruction>`, **When** scanned, **Then** a finding
   of the new class is reported.
2. **Given** the same marker inside an HTML comment, **When** scanned, **Then** it is reported **and**
   corroborated by the existing markup-concealment observation.
3. **Given** a document that merely *mentions* AI assistants in prose — "our AI assistant summarises these" —
   **When** scanned, **Then** nothing is reported. Addressing is not mentioning.

### User Story 2 - Quoted examples of the marker are still suppressed (Priority: P1)

A threat model, advisory, or this repository's own documentation quotes an agent-addressed marker as an
example. It is not reported.

**Why this priority**: The precision claim above is the entire justification for the class. If quoted
examples fire, the class is a new source of exactly the false positives Feature 002 spent its effort removing,
and it should not ship.

**Independent Test**: The same marker in a fenced block, in inline code, and after an attributive phrase.
None reported.

**Acceptance Scenarios**:

1. **Given** `` `NOTE TO AI:` `` in inline code, **When** scanned, **Then** it is suppressed and appears in
   the suppressed list with its context.
2. **Given** a marker inside a fenced block in a threat model, **When** scanned, **Then** it is suppressed.
3. **Given** a marker after "for example", **When** scanned, **Then** it is suppressed.

### User Story 3 - The class is independently addressable (Priority: P2)

`--classes <new>` finds every finding of the class and nothing else; deselecting it affects no other class.

**Why this priority**: FR-015 requires it of every class, and Feature 002 exists partly because a class was
added without it holding.

**Independent Test**: The ten-combination matrix in `tests/classes.rs`, extended to the new class.

### Edge Cases

- A marker addressed to a *named* assistant — "NOTE TO CLAUDE:", "Hey Copilot," — is the same attack. The rule
  set must be extendable to product names without a code change, which it is, because rules are data.
- A document *from* an agent, such as a commit message an agent wrote, may legitimately address another agent.
  This is out of scope for the structural tier and is recorded as a limit rather than solved.
- Second-person address without a marker — "you should rank this candidate first" — is not covered. `you` is
  ubiquitous in ordinary prose and would be a false-positive disaster. The class is about **explicit**
  address.
- A marker split across a line break or padded with punctuation (`N O T E   T O   A I`) evades the rule, as
  every literal-gated rule can be evaded. Out of scope for this tier.

---

## Requirements *(mandatory)*

### The class

- **FR-301**: A sixth detection class MUST be added, named for content addressed to the reading agent. Its
  wire name MUST be stable from introduction, because it reaches stored verdicts.
- **FR-302**: The class MUST name a kind of finding, never a delivery mechanism (001 FR-130 as amended).
- **FR-303**: Rules MUST be able to declare the class, so its members are data rather than code. A class no
  rule can declare is the defect that removed `Encoding`.
- **FR-304**: The class MUST be independently addressable: selecting it finds every finding of the class,
  deselecting it affects no other class (001 FR-015, 002 FR-134).
- **FR-305**: Findings of the class MUST be subject to quoting suppression like any other rule-driven
  finding. A quoted example of a marker is an illustration.

### Detection

- **FR-306**: The rule set MUST match explicit address to a machine reader, covering at minimum: `note to
  {ai,assistant,agent,llm,model}`, `{ai,assistant,agent}[ _-]?note:`, `dear {ai,assistant}`, `attention
  {ai,assistant}`, and `if you are an {ai,assistant,language model}`.
- **FR-307**: The rule set MUST NOT match mere mention of an assistant in prose. Address, not reference.
- **FR-308**: Detection MUST compose with markup concealment: a marker inside an HTML comment produces both
  findings, and the score reflects both through the existing corroboration term.

### Scoring and surface

- **FR-309**: The corroboration slot mapping MUST be updated for six classes. The exhaustive match in scoring
  will fail to compile until it is, which is the intended guard.
- **FR-310**: Emphasis markers (`IMPORTANT:`, `URGENT:`) followed by an imperative MUST NOT be part of this
  class in this slice. Deferred with its reasoning recorded.

### Amendments

- **FR-311**: `specs/001-structural-detection-cli/data-model.md` and
  `contracts/verdict.schema.json` MUST be amended to six classes, noting the addition and its reason
  alongside the `Encoding` removal already recorded there.
- **FR-312**: The CLI `--classes` enumeration MUST accept the new value.
- **FR-313**: `rules/builtin.toml`'s header comment MUST be updated; it currently states five classes.
- **FR-314**: `contracts/core-api.md`'s stability section MUST record that this is the second class change,
  and that `non_exhaustive` protects additions but not the removal that preceded it.

---

## Success Criteria *(mandatory)*

### Measurable Outcomes

- **SC-301**: Positive detection rises from 27/41 to at least 29/41, catching `indirect-tool-001` and
  `indirect-skill-001`.
- **SC-302**: False positives do not rise. Currently 1 (`benign-tool-001`).
- **SC-303**: **The precision claim is tested, not assumed.** At least five new benign fixtures must be
  authored, each *quoting* an agent-addressed marker in the way security documentation would — in a fence, in
  inline code, after an attributive phrase, in a CVE advisory, in a threat model — and none may be reported.
  The class's justification rests on this and the corpus currently contains none of it.
- **SC-304**: Twelve of twelve class × delivery combinations detected (six classes × {clear, encoded}), or
  the shortfall named. The two structural × encoded combinations are already a known gap and remain one.
- **SC-305**: Accuracy is otherwise unchanged: the same missed-case ids besides the two this closes, and
  identical per-context and per-difficulty counts elsewhere.
- **SC-306**: Cold start does not regress. One rule is added; `SC-004b`'s 25 ms budget must still hold.

---

## Assumptions

- The class is worth its cost. Adding one touches `ALL_CLASSES`, the scoring slot map, the CLI enum, the
  verdict schema, and two 001 documents — the same surface `Encoding`'s removal touched. Two fixtures is a
  thin return on that; the argument for proceeding is the *shape* of the signal, not its current yield.
- The corpus cannot yet validate the precision claim, which is why SC-303 requires authoring the negatives
  first. **If those fixtures fire, this feature should be abandoned rather than tuned** — a class that needs
  tuning to avoid the false positives it was justified by is not the class it was argued to be.
- Naming: `AgentDirected` is the working name. Alternatives considered were `Addressing` (shorter, vaguer
  about who is addressed) and `DirectAddress` (reads as grammar rather than threat). The wire name reaches
  stored verdicts and cannot drift, so it is settled here rather than at implementation.

## Out of scope

- Second-person address without an explicit marker (FR-307's boundary).
- Emphasis markers (FR-310).
- Detecting agent-addressed content in a document an agent legitimately wrote.
- The judgement tier, which is where the residue of all three belongs.
