# Plan: detection for the agentic coding-assistant surface

**Branch**: `005-agentic-surface` | **Date**: 2026-08-26 | **Spec**: [spec.md](./spec.md)

**Input**: [spec.md](./spec.md), the three papers in `docs/research/`, and the probe run recorded in the
spec's evidence table.

---

## Summary

Five of six documented agentic attacks return `clean`. Four of the five miss for one shared reason — every
structural rule anchors to a line start with a hand-written prefix character class, and every structured
container introduces a prefix character that is not in it. Agentic artifacts are structured containers by
construction.

So the feature is sequenced as one engine change, then rules on top of it:

1. **A frame boundary** derived from the pre-pass that already walks the input, and a declarative
   `anchor = "frame"` rule field that replaces the per-rule prefix classes.
2. **An eighth class, `Privilege`** — content that widens the agent's own authority rather than acting on
   state outside it.
3. **Rules** for permission widening, agentic credential acquisition, and fetch-and-execute.
4. **Non-text targets** routed to the `incomplete` channel in the CLI, not the core.
5. **A purpose-authored agentic corpus**, reported separately, with negatives of the same shape.

The frame is first because it is the only irreversible-feeling change, and because SC-503 is written so a
bad measurement ends the feature instead of starting a tuning exercise.

## Technical Context

| | |
|---|---|
| Language | Rust 1.85 (toolchain 1.96.0) |
| New dependencies | **none**, in any shipping crate |
| Crates touched | `please-core` (structure, ruleset, detect, finalize), `please-cli` (args, target), `please-eval` (corpus) |
| Crates untouched | `please-judge` — the judged verdict carries classes it does not enumerate |
| Testing | `cargo test --workspace`, fixtures, proptest, trybuild, `please-eval run`/`gate` |
| Target platform | native + `wasm32-unknown-unknown` |
| Performance | frame computed inside `QuotingMap::build`; no second pass, no new allocation per scan |
| Constraints | 27-crate pin, core isolation, ~9.6 MB/s sustained must not fall |

## The constraint this is built inside

Four checks bound every decision below. None of them is negotiable by this feature, and each has already
caught something.

| | |
|---|---|
| `ci/check-core-isolation.sh` | no `std::net`, `std::fs`, `std::process`, `std::time` in `crates/core/src` |
| `ci/check-dependencies.sh` | `please-core`'s shipping graph is exactly 27 crates |
| `wasm32-unknown-unknown` | core builds for a target with no sockets and no `Instant` |
| `clippy --workspace --all-targets -D warnings` | clean, always |

Two more, specific to this feature:

- **`tests/seams.rs` asserts exactly one `Verdict::new(` call site.** Nothing here constructs a verdict;
  the new class flows through `finalize` like the seven before it.
- **`tests/compile_fail/`** asserts that a detector cannot construct a `Reason` or declare a coverage gap.
  FR-516's `incomplete` entry is therefore produced by the CLI's target layer handing the core *nothing*,
  not by a detector declaring a gap. See D6.

## Constitution Check

*Gate: evaluated before Phase 0 and re-checked after design.*

| Principle | Assessment |
|---|---|
| **I — Judgement separate from enforcement** | **Strengthened.** FR-516 replaces findings-on-binary with an explicit `incomplete` naming the reason, which is the principle's own words. `Privilege` exists so a caller can express "block the guardrail attack, log the ordinary directive" — a policy distinction it currently cannot make. |
| **II — Bounded, linear-time** | **Held, and it is the risk.** The frame is computed in the existing single pass over the input and stored as sorted boundaries; lookup is a binary search per match, and match counts are already bounded. No rule added is anchored by look-around, which `regex` cannot express anyway. SC-509 measures it rather than asserting it. |
| **III — Rules are data** | **Strengthened.** The anchor moves *out* of pattern syntax and into a reviewable `anchor = "frame"` field. Today a reader must decode `^[\s>*+\-•\d.)\]]{0,8}` to know a rule is line-anchored; after this they read one word. Every new detection is a rule, not code. |
| **IV — Stratified and honest evaluation** | **Held, with one obligation this feature owes.** FR-519 requires the agentic corpus be reported separately and never blended — the constitution's exact wording for the under-covered indirect case. SC-503/504 make the frame's cost a gate on the committed slices rather than a claim. FR-524 corrects `docs/limits.md`, including a guarantee the probe shows is not holding. |
| **V — Embeddable, dependency-free core** | **Held.** No new dependency in any shipping crate. FR-517 puts the text/non-text decision in the CLI precisely because the core takes bytes; putting it in the core would give the core an opinion about files, which is what keeps it out of a browser. |

**Scope constraints**: in scope by the constitution's own list ("tool results, fetched pages, and tool or
server descriptions"). The spec declares four out-of-scope vectors from the taxonomy it draws on, which is
the no-silent-truncation rule applied to coverage claims rather than to output.

**No deviation to record in Complexity Tracking.** The one judgement call — an eighth class — is argued
against the same FR-130 bar that removed `Encoding` in 002 and added `AgentDirected` in 003; see D3.

## Project Structure

```text
specs/005-agentic-surface/
├── spec.md
├── plan.md          ← this file
└── tasks.md

crates/core/src/
├── structure.rs     ← frame boundaries, in the existing pass (D1)
├── ruleset/parse.rs ← `anchor` field (D2)
├── detect/mod.rs    ← frame filter, beside apply_suppression (D2)
├── finalize/
│   ├── types.rs     ← DetectionClass::Privilege (D3)
│   └── score.rs     ← corroboration slot, 8 classes (D3)
crates/cli/src/
├── args.rs          ← --classes accepts privilege
└── target.rs        ← text/non-text, incomplete channel (D6)
rules/builtin.toml   ← anchors declared; new rules (D4, D5)
crates/eval/corpus/  ← agentic vectors + shadow negatives (D7)
docs/limits.md       ← three corrections (D8)
```

---

## D1 — The frame is a third collection in the structure pre-pass

`QuotingMap::build` already makes one linear pass over the input, splitting on lines for fences and block
quotes and then walking bytes for inline code and quoted strings. It already knows where a line begins,
where an HTML comment opens, and whether the document looks like JSON. Every input the frame needs is
already in that function.

So the frame is a third sorted collection alongside `regions` and `concealing`, and lookup is
`frame_at(offset) -> bool` by binary search — the same shape as `context_at`.

**Why a separate collection rather than a flag on `regions`.** The existing code has this exact argument
in it, about `concealing`:

> Holding them in the same vector with a "does this one suppress?" flag would put the guarantee in every
> reader's hands; two collections put it in the type.

The frame is a third meaning — *a unit starts here* — with a third set of rules about who may consult it.
Same argument, same answer.

**What counts as a frame boundary** (FR-502):

| Boundary | Why |
|---|---|
| start of input | a document begins a unit |
| start of line, after list/quote/heading markers | what the current anchors approximate |
| after `.!?;:` and whitespace | a sentence begins a unit — closes the `. SYSTEM:` miss |
| after a markdown table cell `\|` | a cell is a unit; closes the recorded table-cell miss |
| after an HTML comment open `<!--` | closes row 4 of the probe |
| at the start of a JSON/YAML string value | closes rows 1 and 5 |

The last one leans on `looks_like_json`, which the module already computes for a different purpose. That is
reuse, not coincidence: both questions are "is this quote syntax or attribution", asked from two sides.

**Renaming.** `QuotingMap` now carries three things and only one of them is quoting. It becomes
`StructureMap`, which is what the module is already called. Mechanical, and a rename is cheaper now than
after the type reaches a third consumer.

## D2 — The anchor becomes rule data, and the alternatives were worse

`Rule` gains `anchor`, defaulting to `Anywhere`:

```toml
[[rule]]
id = "boundary.forged_role_marker"
anchor = "frame"
pattern = '(?i)(\[|<\|)?(system|assistant)\s*(\]|\|>)?\s*:'
```

The `^[\s>*+\-•\d.)\]]{0,8}` prefix leaves the pattern. The engine drops a match whose start is not at a
frame boundary, in `detect/mod.rs` beside `apply_suppression`.

**This has a precedent in the codebase, which is the argument.** `fires_in_quotes` is already a declarative
rule field consumed by a post-match filter in exactly that function. The anchor is the same construction
for the same reason, and a reviewer who understands one understands the other.

**And the frame has already been invented three times, inside the patterns.** `grep -n '{0,8}' rules/`
returns three rules. Two of them —`solicitation.actionable_disclosure` and
`external_action.actionable_directive` — do not merely anchor to a line; they carry an alternation that
*is* a frame, hand-rolled into the regex:

```
(?:^[\s>*+\-•\d.)\]]{0,8}|[.!?:;,]\s+|\bplease\s+|\band\s+(?:then\s+)?|\bthen\s+|\byou\s+(?:must|should|…)\s+)
```

The experimental copy in `rules/experimental/actionable-directive.toml` carries the same construct twice
more, and **the four are not identical**. Three read `[.!?:;,]\s+|…|\band\s+(?:then\s+)?|\bthen\s+|…`;
the fourth — `actionable-directive.toml:60` — drops the comma *and* both the `and then` and `then`
branches. So a directive after a comma, and a directive introduced by "and then", are framed by three
rules and not by the fourth, for no recorded reason. Four hand-maintained copies of one concept, already
drifted, in a file whose entire premise is that rules are reviewable data. This is not a design being proposed so much as one being extracted from
where it already is and given a name.

**Two alternatives, both rejected on this repository's own recorded history:**

*Widen each pattern's prefix class to include `<!--`, `|`, `"`.* This repeats the defect once per rule and
needs N edits the next time a container appears — which is how one defect came to be recorded in
`docs/limits.md` as two unrelated open rules. Rejected.

*Normalise the document — strip container syntax, then match.* Rejected on the entry `docs/limits.md`
already carries: **"A whole-input transform is a copy of the document that suppression does not cover."**
Status on that entry is *"the instance is fixed; the class remains open."* Reopening the class to fix a
different bug is the trade this project has already made once and written down.

**Ordering.** The frame filter runs **before** suppression, and suppression is untouched (FR-504). A frame
boundary inside a fence is still inside a fence. The two questions are independent and stay independent —
which is also why User Story 1 scenario 4 exists as a test.

## D3 — `Privilege`, and the bar it has to clear

002 *removed* a class for failing FR-130; 003 added one only after arguing it past the same bar. An eighth
gets the same treatment.

**Does it name a kind of finding?** Yes. "Enable auto-approval" is not how something arrived; it is what
the text is.

**Is it distinct from the seven that exist?**

| Class | Would it cover permission widening? |
|---|---|
| `Override` | No. Nothing is asked to be disregarded; what is permitted *going forward* is widened |
| `Boundary` | No. Forging **claims** authority; this **acquires** it |
| `Solicitation` | No. It extracts nothing; it changes a setting |
| `AgentDirected` | No. That is who is being addressed; this is what is being asked |
| `Concealment`, `Confusable` | No. Both are mechanisms |
| `ExternalAction` | **This is the one to be careful about** — see below |

**The `ExternalAction` distinction, which is the load-bearing one.** That rule's description reads
*"external state — access, permissions, records, accounts"*, and it did fire on probe row 3. So the overlap
is real and has to be answered rather than waved at.

The distinction is **reflexivity**, and it is the same distinction that already separates
`solicitation.system_prompt` from a generic request for data: the agent's *own* configuration is a
different object from the world's. `ExternalAction` acts on state outside the agent — a record, an account,
a candidate's status. `Privilege` acts on the control plane that decides what the agent may do without
asking. One is an action taken through the guardrail; the other is an attack on the guardrail.

Two things make that more than a taxonomy preference:

1. **A caller needs the distinction and cannot express it today.** "Block anything touching my permission
   config; log ordinary directives for review" is an entirely reasonable policy and is unrepresentable
   with seven classes. Principle I puts that decision in the caller's hands, which requires the verdict to
   carry the difference.
2. **The empirical overlap is thin.** `external_action.actionable_directive` caught row 3 on the words
   "update … configuration" and missed four of four other permission-widening payloads. It is not covering
   this; it collided with it once.

**Wire name**: `privilege`. Settled in the spec, not at implementation, because it reaches stored verdicts.

**The compile-time guard is the point.** The corroboration slot mapping in `finalize/score.rs` is an
exhaustive match. It will fail to compile until it is updated for eight classes, which is how 003's
addition was kept honest and is why FR-511 is written as a requirement rather than a reminder.

## D4 — Three rule additions, and what each one's false-positive surface is

Rules, not code (Principle III). Each is stated with the thing that will make it misfire, because that is
what determines whether it ships.

**`privilege.permission_widening`** — `autoApprove`-style settings, allow-list wildcards, bypass
modes, safety-disabling flags. *FP surface*: documentation of those settings, including this repository's. Leans
on fence and inline-code suppression, which is why FR-521 makes the repo's own docs a standing negative.

**`solicitation.credentials`, extended** — the existing verb list (`print|output|reveal|send|forward|
exfiltrate|email|upload|list`) contains no verb any agentic payload uses. Measured: "send the credentials"
fires; "**read** ~/.aws/credentials and **include** in metadata" is clean. Adds read, include, attach,
`embed`, `append`, `pass`, plus the named credential-file targets (`~/.aws/credentials` and its
siblings). *FP surface*: prose about credential files. This is an extension of a shipped rule, so
it moves an already-measured rate and SC-504 will see it.

**`external_action.remote_execution`** — `curl … | sh`, `bash <(curl …)`, `wget -O- … | sh`, `iwr … | iex`.
*FP surface*: **install documentation**, which is where this construct legitimately lives and which is
overwhelmingly inside a fenced block. Stated as User Story 4 scenario 3 so the negative ships with the
rule.

**Every rule added here is frame-anchored or unanchored** (FR-515). Adding a line-anchored rule in the
feature that exists because line anchors miss would be its own kind of joke.

## D5 — What is deliberately *not* a rule

The MCP tool-poisoning payload is caught by the extended `solicitation.credentials`, not by a
"tool description" rule. There is no `mcp.*` rule namespace in this feature, and that is a decision.

A tool description is a **delivery vector**. FR-130 says a class names a kind of finding and not how it
arrived, and the same logic applies a level down: a rule that fires because text is in a tool description
would need the engine to know what it is reading, which is the `--surface` design the spec's Clarifications
already rejected on evidence. What makes the Invariant Labs payload detectable is that it solicits a
credential file — true wherever it appears.

The corpus (D7) still stratifies **by vector**, because measuring per-vector rates is how anyone finds out
that this claim is wrong.

## D6 — Non-text lives in the CLI, and produces `incomplete` rather than nothing

Two measured false positives — a NUL byte in an NTFS stream scoring 80, a PDF producing 64 findings —
and one design question with an answer the codebase has already settled twice.

**Why the CLI and not the core.** The core takes bytes and has no concept of a file; `check-core-isolation.sh`
forbids `std::fs` for exactly this reason, and the wasm32 build is the corroboration. A caller passing a
decoded string should never have their input second-guessed. `crates/cli/src/target.rs` is where a walk
already decides what to open, and it is where this belongs.

**Why `incomplete` rather than skipping.** Principle I: absence of analysis is never absence of risk. A
binary that vanishes from the output reads as a clean scan. The verdict type already carries an
`incomplete` channel with a reason, and this is what it is for. FR-518 makes it visible; the constitution's
no-silent-truncation rule is the same requirement said differently.

**The test is UTF-8 validity plus a NUL check, not a byte-frequency heuristic.** A heuristic that guesses
"text-like" would mis-classify exactly the inputs the project has spent effort protecting: dense
non-English prose, and text carrying legitimate zero-width joiners in emoji. Scenario 3 of User Story 5 is
written to fail if this drifts toward a heuristic.

**A note the walk owes the reader**: a PDF *does* contain extractable text, and an attacker can put a
payload in one. Declining to parse PDFs is a scope boundary, not a solved problem, and it goes in
`docs/limits.md` as one (FR-524).

## D7 — The corpus is purpose-authored, stratified by vector, and shipped with its shadow

The constitution requires it: *"Coverage of the artifact-scanning case therefore requires a purpose-authored
corpus, which MUST be reported separately from public-corpus metrics and never blended into them."*

**Positives**, one stratum per SoK vector this feature claims: D2.1 rules-file backdoor, D2.2 manifest
injection, D3.1 tool poisoning, D3.1 rug-pull description, P2.1 config modification, plus the toxic-issue
comment case. Carriers already exist for several — `mcp-tool-description.txt`, `skill-file.md`,
`issue-body.md` — and the generator varies placement independently of payload, which is what produced the
most useful result in the last evaluation and will do it again here.

**Negatives shadow positives one-for-one** (FR-520). Every positive has a legitimate artifact of the same
*shape*: a real `.cursorrules`, a real MCP manifest, a real skill file, and a CVE write-up quoting the
payload. This is the SC-303 construction from 003 — author the negatives first, and abandon rather than
tune if they fire.

**Then a free one.** FR-521 makes this repository's own `docs/`, `rules/`, and `README.md` a standing
negative. It costs nothing, it is adversarial by accident — this project documents payloads more densely
than any real corpus — and it currently reports **8 non-clean of 25**.

**What the corpus cannot do**: it is written by the same people who wrote the detectors, which is the bias
`README.md` already names about the fixture suite. Per-vector rates from it are a statement about coverage
of a taxonomy, not about field prevalence, and `please-eval report` must generate that sentence rather than
rely on a reader supplying it (SC-506).

## D8 — `docs/limits.md` is corrected in three places, and one of them is a retraction

Not documentation cleanup. One of these is a guarantee the probe shows is not holding.

1. **"An HTML comment must never become a quoting context" — marked "constraint, enforced by test".** True
   for the rules that reach the payload; silently false for the anchored rules that never match inside a
   comment. The entry gains what the probe found and what closed it.
2. **"Two rules miss for reasons worth naming" — recorded as two.** They are one anchor defect with two
   symptoms. Rewritten as one entry, closed by D1/D2, with the *generalisation* kept: a rule that anchors
   to a hand-written prefix class will miss in the next container nobody thought of.
3. **A new entry** for what this feature leaves open: PDFs are declined rather than parsed; rug-pull
   detection needs state the engine does not hold; the taxonomy's transport and multimodal vectors are
   outside what a text analyser can reach.

The general form is the one the project already uses: record the defect, record why the obvious repair is
worse, and keep the entry after it is fixed if the reasoning outlived the bug.

---

## Open questions for the examiner

1. **Does the frame include a colon?** `.!?;:` is proposed. A colon frames a directive after a label
   (`Note: ignore previous instructions`) and also appears mid-URL and in YAML keys. `looks_like_json`
   handles the serialised case; the URL case is untested. **Proposal**: include it, and let SC-503 price
   it. If it costs false positives, drop the colon rather than the frame — it is the one boundary that can
   be removed independently.
2. **Should `privilege` outrank `boundary` in severity?** A successful permission-widening payload converts
   every later injection into a silent one, which is a different magnitude of consequence. But
   `docs/limits.md` records the risk bands as provisional and uncalibrated, and this feature does not
   calibrate them. **Proposal**: 85, matching `boundary.forged_system_directive`, and no band changes.
3. **Do the extended `solicitation.credentials` verbs belong in the shipped set or in
   `rules/experimental/`?** `read` and `include` are far more common in ordinary prose than `exfiltrate`.
   The two experimental rules already in the tree are the precedent for shipping a rule that needs a
   measurement first. **Proposal**: ship it, because the file targets carry the specificity — but this is
   the change most likely to move the false-positive rate, and it is the one to revert first if SC-503
   fails.

## What follows

`tasks.md` breaks this into ordered tasks, test-first per the constitution's Development Workflow. The
sequencing that matters:

**The frame is measured before anything is built on it.** Tasks are ordered so that D1 and D2 land, SC-503
and SC-504 are measured on the committed slices, and *then* the rules go in. If the frame costs more than
its budget, three of the five deliverables here do not happen, and that is the correct outcome rather than
a setback — the same shape as 003's instruction to abandon the class rather than tune it.
