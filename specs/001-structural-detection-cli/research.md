# Phase 0 Research: Structural Detection & Scan CLI

**Feature**: `001-structural-detection-cli` | **Date**: 2026-08-15

Corpus facts referenced here are measured in [`docs/research/corpus-analysis.md`](../../docs/research/corpus-analysis.md).

---

## D1 — "No dependencies" is the wrong constraint; the right one is what Principle V names

**Decision**: `please-core` takes a small, audited set of pure-Rust dependencies —
`regex`, `aho-corasick`, `unicode-security`, `unicode-normalization`, `base64`, `toml`, and
optionally `serde`. It does not attempt zero dependencies.

**Rationale**: The feature brief asked for a "no-dep" core, which is stricter than the constitution
actually requires. Principle V's testable claims are: no async runtime, no network I/O, no required
model download, and a proven `wasm32-unknown-unknown` build. Every crate above satisfies all four.
Zero-dependency would mean hand-writing a multi-pattern matcher and a Unicode confusables table
inside a security tool — replacing well-tested code with new code in exactly the component whose
correctness is the product.

The tension is worth naming rather than silently resolving: the plan adopts the constitution's
version of the constraint, and enforces it by test (D11) rather than by intention.

**Alternatives considered**: Hand-rolled matcher — rejected, concentrates novel risk in the
security boundary. `regex-lite` — retained as a wasm binary-size lever (D12), not as the default.

---

## D2 — Match iteration is quadratic; bounded match collection is what restores linearity

**Decision**: Every rule collects at most `max_matches_per_rule` matches (default 16), and a scan
collects at most `max_reasons` reasons (default 64) in total. Collection stops at the cap.

**Rationale**: This is the finding that would otherwise have broken SC-005 and FR-016 silently. The
`regex` crate guarantees `O(m·n)` for a *single* search (`is_match`, `find`), but explicitly states
that **iterators are `O(m·n²)`**, because an iterator performs a fresh search per match. A scanner
needs all matches, so the natural implementation — `find_iter` per rule over the input — is
quadratic in input length. On the 82 KB inputs the corpus already contains, that is the
denial-of-service vector Principle II exists to forbid, introduced by the detector itself.

Capping matches at a constant `K` makes the per-rule cost `O(K·m·n)`, which is linear in `n` for
fixed `K`. The same cap is what FR-007 independently requires (bounded reasons, with omission
declared), so one mechanism discharges FR-007, FR-016, and SC-005 together. When a cap truncates,
the verdict records it, satisfying the constitution's "no silent truncation" constraint.

**Alternatives considered**: `regex-automata` in "earliest" mode, which restores the linear bound at
the cost of greedy semantics — held in reserve if profiling shows the cap is insufficient. Accepting
quadratic behaviour — rejected; it is a constitutional violation.

---

## D3 — Caller-supplied rules are an attack surface on the scanner itself

**Decision**: Rule compilation enforces three limits, and exceeding any of them is a rule-set load
failure per FR-024: a maximum pattern source length, a maximum compiled program size via
`RegexBuilder::size_limit`, and a maximum rule count per set.

**Rationale**: `regex`'s documentation is explicit that untrusted *patterns* are far more dangerous
than untrusted input: `a{5}{5}{5}{5}{5}{5}` is 20 characters of source that expands to `a{15625}`
and a correspondingly enormous automaton. FR-023 lets a caller supply their own rules, which makes
this reachable in normal use — a copied-in rule set from a third party is a supply-chain path into
memory exhaustion.

This is a gap in the specification rather than in the plan: FR-024 currently covers *malformed*
rule sets, and a resource-exhausting rule is well-formed. Recommended as a spec amendment
(see plan Complexity Tracking).

**Alternatives considered**: Trusting rule authors — rejected; the tool's own threat model assumes
inputs are hostile, and a rule set is an input.

---

## D4 — Cold-start cost, not per-scan cost, is the budget that actually binds

**Decision**: Two-stage matching. A single literal prefilter (`aho-corasick`, built once from every
rule's required literals) runs first; a rule's full pattern is compiled lazily and only if its
literal gate hits. Performance is budgeted and measured as two separate numbers: cold start
(process launch to first verdict) and warm per-scan throughput.

**Rationale**: SC-004 asks for a verdict within 10 ms at the 95th percentile. The intended consumer
is a pre-tool hook that launches `plz` once per tool call, so the wall-clock a caller experiences
includes process start, rule-set parse, and pattern compilation. Compiling on the order of a
hundred patterns eagerly is plausibly tens of milliseconds on its own — the budget would be spent
before any input was examined, and the failure would look like "the tool is slow" rather than "the
design was wrong".

Two-stage matching removes the cost for the common case: text that hits no rule literal compiles no
patterns at all. It also makes the cost profile legible — a scan is fast because nothing matched,
not because a heuristic gave up.

SC-004 is ambiguous about which budget it names; the plan treats it as the warm per-scan figure and
sets a separate explicit cold-start budget, flagged for confirmation.

**Alternatives considered**: Eager compilation — rejected on the budget above. Serialized
pre-compiled automata via `regex-automata` — real and worth revisiting, but a significant build-time
mechanism to adopt before profiling proves it necessary. A resident daemon — rejected; it adds a
lifecycle, an IPC surface, and a trust boundary to a tool whose value is being a single static
binary.

---

## D5 — Encoded content is reported only when what it decodes to is itself a finding

**Decision**: Decoders never emit a finding for the mere presence of an encoding. A transformation is
reported only when re-scanning its decoded output produces a rule hit; the reason then carries the
transformation chain and the decoded content that triggered it. Decoding is bounded by depth
(default 3) and guarded against cycles by hashing already-visited decoded buffers.

**Rationale**: "This text contains base-64" is not a security finding — it is a description of most
configuration files, every embedded certificate, and every content hash. Reporting it would produce
exactly the false-positive flood that SC-003 forbids and that gets a firewall switched off. Making
the decoded content carry the finding means the base-64 detector has no false-positive rate of its
own to speak of: it either decodes to something a rule already recognises, or it is silent.

This also gives FR-011 a natural reading. The five families to cover are the five the corpus labels
explicitly — base-64, hexadecimal, rotation cipher, reversal, glyph substitution — at 1,971 rows
each, which is a directly measurable slice rather than an open-ended list.

**Alternatives considered**: Entropy-threshold flagging of encoded blobs — rejected; it flags
hashes, tokens, and minified assets, and the threshold is unjustifiable. Reporting encodings at a
lower severity — rejected; a finding nobody can act on still trains callers to ignore output.

---

## D6 — Concealment coverage must include the tag block and variation selectors

**Decision**: The concealment detector covers, and where possible decodes: C0 and C1 controls,
zero-width characters (U+200B–U+200F, U+2060–U+2064), bidirectional overrides and isolates
(U+202A–U+202E, U+2066–U+2069), the byte-order mark (U+FEFF), the Mongolian vowel separator
(U+180E), **the Unicode Tags block (U+E0000–U+E007F)**, and **variation selectors (U+FE00–U+FE0F,
U+E0100–U+E01EF)**. Tag-block runs are decoded by subtracting U+E0000 to recover ASCII, and the
recovered text is re-scanned through D5's bounded pipeline.

**Rationale**: The tag block is the highest-value concealment channel currently in use. Riley
Goodside demonstrated it in January 2024: tag characters render as nothing in essentially every UI,
require no terminator, and are understood by models because they occur in training data. Follow-up
work ("Sneaky Bits") showed variation selectors can smuggle arbitrary bytes using only two invisible
characters. A concealment detector that omits these two ranges misses the state of the art while
appearing to cover the category.

Worth reporting back to bee: `src/safe_text.rs` neutralises C0/C1, U+200B–U+200F, U+202A–U+202E,
U+2066–U+2069, and U+FEFF — but **not** the tag block, not variation selectors, and not U+2060. Its
job is display sanitisation rather than detection, so this is not a defect in it, but a tag-encoded
payload currently passes through it unescaped. That is a concrete contribution this project can make
back to its first consumer.

**Alternatives considered**: Stripping rather than reporting — rejected; this feature detects, and
the caller disposes (Principle I). Covering only zero-width and bidi, as most tools do — rejected;
it is the gap an attacker aims at.

---

## D7 — Confusable detection discriminates within a token, not across a document

**Decision**: Confusable analysis applies UTS #39 via `unicode-security` — `skeleton` for
confusable folding, plus mixed-script and restriction-level checks — evaluated **per token**, never
over the whole input. A token mixing scripts in a way that folds onto an ASCII keyword is a finding;
a document containing tokens of several scripts is not.

**Rationale**: This is the requirement most likely to harm non-English users, and the corpus cannot
warn us about it: there are zero non-English attack examples but roughly 79,000 non-English benign
rows, so a naive detector's damage shows up only as false positives on real users' text. Whole-input
mixed-script detection would flag any English document quoting Chinese, which is ordinary technical
writing. The actual attack is intra-token: a Cyrillic `о` inside `ignоre` so that a literal rule for
`ignore` misses while a model still reads the word. Scoping the check to token interiors targets the
attack and leaves multilingual prose alone, which is exactly what FR-010 asks for.

**Alternatives considered**: Whole-document script analysis — rejected as actively harmful. A
hand-maintained homoglyph table — rejected; UTS #39 is the maintained standard and
`unicode-security` tracks it.

---

## D8 — Distinguishing an issued instruction from a quoted one is a structural pre-pass

**Decision**: A linear-time structural pre-pass classifies regions of the input — fenced code, inline
code, block quotes, quoted string literals, and spans following attributive markers ("for example",
"e.g.", "such as", "the phrase", "payload:"). Rules declare whether they fire inside a quoting
region. Matches in quoting regions are suppressed by default, and suppression is recorded so it is
visible rather than invisible.

**Rationale**: FR-014 is the highest-risk requirement in the spec, and the edge case it protects is
the one that decides adoption: a threat model, an advisory, a rule definition, or this specification
all contain override phrases as subject matter. Flagging them makes the tool unusable by the people
most likely to evaluate it — which is why SC-003's hard-negative set is built from precisely that
material.

The honest limit, to be documented in the tool rather than discovered by a user: this is a heuristic
over surface structure, not comprehension. An attacker can wrap a live payload in a code fence and
suppress it. That is an accepted false-negative in this tier, and closing it is what the later
judgement tier is for. Stating the limit is a constitutional requirement, not a courtesy.

**Alternatives considered**: No context gating — rejected; SC-003 is unreachable without it. Full
document parsing per format — rejected as disproportionate for this slice.

---

## D9 — Determinism is a design constraint with concrete consequences

**Decision**: Scores are integers on a fixed `0..=100` scale. No output field derives from hash-map
iteration order, wall-clock time, absolute paths not supplied by the caller, or floating-point
formatting. Reasons are sorted by a total order (input offset, then rule identifier). Ordered
collections are used wherever a set would otherwise be iterated.

**Rationale**: SC-011 requires byte-identical machine-readable output across repeated runs and
across host machines, and FR-030 requires reproducibility, so determinism is a requirement rather
than a nicety — it is what lets a caller cache verdicts and diff them in CI. Each item above is a
known way that requirement breaks in practice; floating-point score formatting and hash-map ordering
are the two most common. Integer scores remove an entire class of cross-platform difference at no
expressive cost, since a calibrated confidence needs two significant figures at most.

**Alternatives considered**: Floating-point scores with fixed formatting — rejected; the formatting
discipline has to hold at every call site forever, whereas integers cannot fail.

---

## D10 — The core cannot read the clock

**Decision**: `please-core` uses no `std::time` API. Timing lives in `please-cli` and in benchmarks.

**Rationale**: `std::time::Instant` panics or misbehaves on `wasm32-unknown-unknown`, which has no
monotonic clock. A timeout implemented inside the core would therefore fail the very target Principle
V requires CI to prove. Bounding work by counted units — input bytes, decode depth, match count —
rather than by elapsed time keeps the core portable and makes bounds deterministic, which D9 needs
anyway. A wall-clock budget belongs to the caller.

**Alternatives considered**: A clock abstraction injected by the caller — rejected as unnecessary
once bounds are counted rather than timed.

---

## D11 — Every constitutional claim gets a mechanical check

**Decision**:

| Claim | Mechanism |
|---|---|
| Linear-time analysis (FR-016, SC-005) | `criterion` sweep across four orders of magnitude, asserting the fitted growth exponent stays within tolerance of 1.0 |
| No crash, hang, or unbounded memory (FR-019, SC-006) | `cargo-fuzz` (libFuzzer) targets on the scan entry point and each decoder, run in CI and long-run out of band |
| Bounds hold universally (FR-007, FR-017, FR-018) | `proptest` properties over generated inputs |
| Never clean on incomplete analysis (FR-004, SC-007) | `proptest` invariant: for any input, outcome is clean only if no bound was hit and no rule fired |
| Dependency gating (Principle V) | guard test asserting the default build's resolved dependency set against a committed allow-list |
| wasm32 build (Principle V) | `cargo build --target wasm32-unknown-unknown -p please-core` in CI |
| Deterministic output (FR-030, SC-011) | `insta` snapshots plus a repeat-and-compare test, run on two host targets in CI |
| Fixture accuracy (SC-002, SC-003) | fixture corpus under version control, per-class assertions, false-positive count gate |

**Rationale**: The constitution says a denial no test exercises is not enforced, and property-based
coverage of the bounds is mandatory rather than optional. Naming the mechanism per claim now is what
makes `/speckit-tasks` able to generate a task per mechanism instead of one vague "add tests" task.

**Alternatives considered**: Example-based tests alone — rejected; explicitly insufficient under the
constitution's quality gates.

---

## D12 — Workspace layout, and what stays out of it

**Decision**: A Cargo workspace containing `crates/core` (`please-core`) and `crates/cli`
(`please-cli`, producing the `plz` binary). `crates/eval` (`please-eval`) is created but listed in
`workspace.exclude` with its own lockfile. `crates/wasm` is deferred to its own feature.

**Rationale**: The evaluation harness needs data-frame and query dependencies far heavier than
anything the shipping crates may carry, and its corpus adapters reach the network. Excluding it from
the workspace means `cargo build`, `cargo test`, and `cargo clippy --workspace` over the shipping
crates are byte-for-byte unaffected by its existence, and the dependency guard in D11 cannot be
defeated by a transitive edge from a dev tool. This is the pattern bee already uses for its `xtask`
crate, and adopting it keeps a contributor moving between the two repositories on familiar ground.

`please-core` sets `#![forbid(unsafe_code)]`. `please-cli` is a thin wrapper holding no detection
logic, per Principle V.

**Alternatives considered**: One crate with feature flags — rejected; the CLI's argument parsing and
filesystem walking would enter the wasm build's dependency graph. Publishing eval as a workspace
member — rejected; it defeats the guard test.

---

# Phase 0 addendum — decisions arising from the 2026-08-15 clarification session

Five clarifications changed the spec after D1–D12 were written. Four are absorbed without
consequence for the design; one required a change to the verdict model itself.

---

## D13 — Score aggregation: maximum plus a bounded distinct-class bonus

**Decision**: `score = min(100, max(severity of firing rules) + bonus)`, where `bonus` adds a fixed
increment (5) for each **distinct detection class** present beyond the class contributing the
maximum, and the bonus is itself capped (15). Aggregation runs over **every** match found, before
`max_reasons` truncates the reported list.

**Rationale**: FR-001 required "a numeric score on a documented fixed scale" but never said how
severities combine, which left the single most consequential constant in the system undefined — it
sets every block/allow outcome and therefore the false-positive rate the constitution makes a merge
gate.

Summing is disqualified by a property that only shows up in production: score would grow with input
length, so a long benign engineering document accumulates innocuous matches until it crosses any
threshold. The tool would then behave worse on exactly the large, important files a team most wants
scanned. Taking the maximum is length-independent but discards corroboration, and corroboration is
real signal here: an override phrase *and* hidden characters *and* an encoded payload in one file is
far more suspicious than any one alone. Counting distinct classes bounds the bonus at six terms
regardless of input size, which buys the corroboration signal without reintroducing length
sensitivity.

Aggregating before truncation matters because D9 orders reasons by byte offset rather than severity,
so truncating first could discard the highest-severity finding and silently understate the score.

**Alternatives considered**: Sum with cap — rejected, length-sensitive. Pure maximum — rejected, no
corroboration. Diminishing-returns sum — bounded, but the resulting score is hard to explain in
output and still counts repeated matches of one rule.

---

## D14 — The verdict model needed a cause channel that is not a limit

**Decision**: Replace `limits_hit` with a single `incomplete` list whose entries carry a
discriminated `cause`. Causes divide into **bounds** (`input_size`, `decode_depth`,
`max_matches_per_rule`, `max_reasons`, `excerpt_length`), which carry the `configured` value that was
in force, and **failures** (`target_unreadable`, `decode_failed`, `ruleset_unavailable`,
`tier_unavailable`), which do not. This is a breaking change to a pre-release contract, made
deliberately now rather than after publication.

**Rationale**: FR-032a — an unreadable file in a directory walk yields an inconclusive verdict — had
nowhere to live. The original model expressed inconclusiveness *only* through `limits_hit`, whose
enum covered five configured bounds, and an unreadable target is not a bound anyone configured. The
same gap applies to a failed decoder and an unavailable optional tier, both of which FR-003 and the
constitution already require to produce a cause.

Unifying rather than adding a second array keeps the FR-004 invariant single-source: `clean` requires
`reasons` empty **and** `incomplete` empty. Two accumulators would mean two places to forget, in the
one check the entire fail-closed posture rests on. The bound-versus-failure distinction survives in
the enum and in whether `configured` is present, which preserves what a caller does about it — raise
a limit, or fix an environment.

**Alternatives considered**: Keep `limits_hit` and add a parallel `failures` array — rejected, splits
the invariant. Model an unreadable target as a usage error — rejected by the clarification itself,
since one locked file would suppress findings in every other file in the tree. Overload
`limit: "other"` with free-text detail — rejected; it makes the cause unmachine-readable, which is
what FR-003 requires it to be.

---

## D15 — No-network is proven by a static gate, not by the dependency allow-list alone

**Decision**: CI enforces a lint denying networking and filesystem interfaces inside `please-core`'s
own sources, alongside the existing dependency allow-list. Runtime verification under network
isolation is available as optional defence in depth on self-hosted capacity.

**Rationale**: The allow-list was the only mechanism pointed at FR-031, and it does not actually
prove the claim: reaching the network in Rust requires no dependency at all, because `std::net` is in
the standard library. So a dependency audit covers a *dependency* opening a socket and is blind to
the engine's own code doing it. The two checks are complementary and each is cheap; the `wasm32`
build corroborates independently, since that target has no ambient network.

**Alternatives considered**: Allow-list only — rejected as insufficient, above. Runtime isolation as
the primary gate — stronger evidence but needs CI plumbing and platform-specific namespacing;
retained as optional. Review only — rejected; the constitution requires mechanical checks for
security-relevant behaviour.

---

## D16 — Absorbed without design change

Three clarifications land entirely in requirements and test tasks:

| Clarification | Effect |
|---|---|
| SC-003 gains a 200-example minimum negative set | Fixture authoring target; no design impact |
| SC-006 becomes a scheduled cumulative campaign with a per-change smoke | CI workflow shape; no design impact |
| SC-001 splits into a mechanical completeness gate plus a recorded per-release walkthrough | The mechanical half was already satisfied by the `Reason` shape, which carries rule identity, class, span, excerpt, and description |

Cold-start budget is now explicit at 25 ms alongside the warm per-scan figure, resolving the
ambiguity D4 flagged. No mechanism changes: two-stage matching was already chosen because of it.
