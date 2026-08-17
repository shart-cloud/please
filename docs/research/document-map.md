# `DocumentMap`: a plan for finding out whether segment-relative detection works

Plan, 2026-08-16. Rationale in `docs/research/indirect-structure.md`.

This is a plan for an **experiment**, not for a feature. Nothing here ships a detector. The output of
Phase 0–2 is a number that says whether the idea in `indirect-structure.md` §2 survives contact with
the corpus, plus the kill criteria agreed in advance so the answer cannot be argued with afterwards.

The discipline is borrowed from `specs/003-agent-directed-class`, which states it well: *"If those
fixtures fire, this feature should be abandoned rather than tuned — a class that needs tuning to
avoid the false positives it was justified by is not the class it was argued to be."*

---

## 1. The shape

`QuotingMap` answers one binary question — *is this region shown rather than said?* — over five
region kinds, and throws the rest of the traversal away. It is already a linear pass that finds line
structure, fences, block quotes, inline delimiters, and comments. The generalisation costs a wider
output type, not a new algorithm.

```text
QuotingMap                                  DocumentMap
  regions:    [(start, end, QuotingContext)]  segments:  [(start, end, SegmentKind, Register)]
  concealing: [(start, end, ConcealingContext)]  regions:    …unchanged, still the suppression map
                                                 concealing: …unchanged
```

`QuotingContext` answers *may a match here be suppressed*. `SegmentKind` answers a different
question — *what kind of thing is this region, and what belongs in one* — and the two must stay
separate collections for the same reason `concealing` is already separate from `regions`: a flag on
one collection puts the guarantee in every reader's hands.

### 1.1 `SegmentKind`

`#[non_exhaustive]`, because this list will grow and `contracts/core-api.md` already records that
additions are protected and removals are not.

| variant | recognised by |
|---|---|
| `Frontmatter` | `---` at byte 0 to the next `---` line |
| `Heading` | `#{1,6} ` at line start |
| `Prose` | default: a run of non-blank lines that is none of the below |
| `ListItem` | `[-*+] ` or `\d+[.)] ` at line start; one segment per item, siblings linked by depth |
| `TableRow` | a line with ≥2 unescaped `|`, or ≥2 runs of ≥2 spaces between non-space fields |
| `KeyValue` | `key: value` / `key = value` at line start, value on the same line |
| `JsonScalarField` | inside `looks_like_json` input: one `"key": <scalar>` pair |
| `CodeFence` | already found by the existing pass |
| `TranscriptCommand` | line beginning `$ `, `> ` in a shell context, `PS>`, `C:\…>` |
| `TranscriptOutput` | lines following a `TranscriptCommand` until the next one or a blank run |
| `SignatureBlock` | after `--\n`, or a trailing `Best,|Thanks,|Regards,|-\s*\w+` line near EOF |
| `WhitespaceGap` | ≥3 consecutive blank lines. **A segment in its own right**, not a separator |
| `Trailing` | the last non-empty segment of the document, as an overlay flag rather than a kind |

Two of these are doing more work than they look:

* **`WhitespaceGap` is a segment, not a delimiter.** `indirect-email-002` hides an imperative behind
  25 blank lines. If gaps are eaten during segmentation, the fact that a gap *preceded* the payload
  is lost, and that fact is the finding.
* **`Trailing` is an overlay, not a kind.** BIPIA's position ablation makes end-of-content the
  highest-ASR placement; a payload is a trailing *list item* or a trailing *prose paragraph*, and it
  needs to keep both facts.

### 1.2 `Register`

The cheap measured profile of a segment. Every field is a count or a ratio derived from counts.

| field | type | measured as |
|---|---|---|
| `bytes`, `lines`, `sentences` | `u32` | counts |
| `imperative_initial` | `u16` per-mille | fraction of sentences opening with a bare verb (no leading subject, no article, no auxiliary) |
| `second_person` | `u16` per-mille | `you / your / yours` tokens per word |
| `first_person` | `u16` per-mille | `i / we / our / my` tokens per word |
| `digit_density` | `u16` per-mille | ASCII digits per byte |
| `punct_density` | `u16` per-mille | ASCII punctuation per byte |
| `upper_density` | `u16` per-mille | uppercase per alphabetic byte |
| `mean_line_len` | `u16` | bytes, saturating |
| `identifier_refs` | `u8` | count of email-shaped, URL-shaped, path-shaped, or long-digit-run tokens |
| `addressee` | enum | `Human`, `Machine`, `None`, `Unclear` — from second-person + vocative + the 003 marker set |

**Every ratio is fixed-point per-mille integer arithmetic. No floats anywhere.** SC-011 promises
byte-identical output for the same input; IEEE-754 basic ops are deterministic but libm and FMA
contraction are not portable, and a risk band that differs between an x86 CI runner and an ARM
laptop is a broken guarantee that would take months to notice. Integers cost nothing here.

`imperative_initial` is the only field needing a real decision. The cheapest workable definition:
a sentence whose first token is alphabetic, lowercase-or-titlecase, not in a small closed stop set
(articles, pronouns, prepositions, auxiliaries, conjunctions, `the/this/that/there/it/we/i/…`), and
not followed by a copula. That is a crude verb detector and it will misfire. It is also 40 lines and
no dependency, and the point of Phase 0 is to find out whether crude is enough.

### 1.3 The outlier score

Not a detector. A number the probe reports.

For each segment, for each `Register` field, compute the deviation from the **sibling distribution**
— the other segments of the same `SegmentKind` in the same document, falling back to all segments
when there are fewer than three siblings. Sum absolute per-mille deviations, normalised by the
document's own spread, in fixed point. Report the ranked list.

Sibling-relative rather than document-relative is the whole design. A table row is not anomalous for
having a high digit density; it is anomalous for having a *low* one when every other row is numeric.
That is `indirect-email-007` exactly.

---

## 2. Where it goes in the pipeline

**Phase 0–2: nowhere.** `DocumentMap::build` is a new function nobody in `engine.rs` calls. The
probe is an example binary and a test. The shipped scan path is byte-identical, `--judge` behaviour
is untouched, and no verdict changes. This is deliberate: the experiment must be cheap to abandon.

**If it survives, Phase 4 merges traversals rather than adding one.** `docs/limits.md` is explicit
that the pipeline is three linear passes composing to 6.5 MB/s against a 10 MB/s criterion, and that
*"making any single pass twice as fast buys about 15% — reaching 10 MB/s means one fewer pass, or
passes that share one traversal."* Segmentation and quoting classification examine the same lines
for the same delimiters. Folding them is aligned with the remedy `limits.md` already names; bolting
a fourth pass on would take throughput to roughly 5 MB/s and make SC-004a worse, which is not
acceptable for an unproven signal.

**Constitutional check, done now rather than at review:**

| principle | effect |
|---|---|
| II — bounded, linear-time | Segmentation is one pass, bounded by input length. `Register` is counters. Sibling comparison is O(segments) per field. **Segment count must be bounded** like `max_matches_per_rule` is, or a document of 200,000 one-character list items is a resource bomb |
| III — rules are data | A register outlier is a **mechanism**, so it is code, like `concealment` and `confusable`. But its *thresholds* are calibration and belong in the rule set beside `[bands]`, not as constants — the same argument that put band boundaries there |
| V — dependency-free core | No new dependencies. Byte arithmetic and the existing traversal |
| SC-011 — determinism | Held by the fixed-point rule in §1.2 |

---

## 3. The corpus this needs

19 indirect fixtures and 17 benign cannot answer the question, and the reason is not sample size —
it is that every hypothesis here is about a **span** and every label we have is about a **document**.

`indirect-structure.md` §5 argues for a generator. Concretely:

```
crates/eval/            (already excluded from the workspace, already has its own lockfile)
  corpus/carriers/      benign documents by format: email, meeting notes, invoice,
                        grep output, shell transcript, SKILL.md, JSON tool result,
                        MCP tool description, CI log
  corpus/payloads/      attacker instructions, tagged by intent (direct harm / data
                        stealing, per InjecAgent's taxonomy)
  corpus/positions.toml prepend | first-paragraph | mid-paragraph | list-item |
                        table-cell | json-field | post-signature | post-gap | trailing
  src/generate.rs       carrier × payload × position → JSONL
```

Each generated row carries `carrier_id`, `payload_id`, `position`, and — the point of the exercise —
`injected_span: [start, end]`. Each carrier also emits **unmodified**, as a matched negative:
identical in every respect but the payload.

Three properties this gives that no download does: span-level ground truth, independent ablation of
position against carrier, and a matched negative per positive. Generated text is ours, so unlike the
41 upstream sources in `corpus-analysis.md` it can be committed.

**Target for Phase 1: ~12 carriers × ~20 payloads × 9 positions ≈ 2,160 positives + 12 negatives**,
plus the 36 existing hand-written fixtures held out entirely and never used to choose a threshold.

---

## 4. Phases

Each phase has an output that is a number or a file, and each is independently abandonable.

### Phase 0 — segment and look (no metric yet)

* `crates/core/src/document.rs`: `SegmentKind`, `Register`, `DocumentMap::build`.
* `crates/core/examples/segment.rs`: read a file, print segments with kind, register, and rank.
* Run it by hand over all 36 hand-written fixtures.

**Exit:** the segmentation is *legible* — a human reading the output for `indirect-email-007` sees
the account-number field as its own segment. If segmentation cannot even isolate the payload into a
segment of its own, no downstream metric can recover, and the answer is "the carrier formats are too
irregular for a rule-based segmenter" before any corpus work is paid for.

### Phase 1 — the generator

* `crates/eval/src/generate.rs` and the corpus tree in §3.
* Output: `crates/eval/corpus/generated.jsonl` with span labels.

**Exit:** a JSONL file, and a spot check that 20 random rows read as plausible documents rather than
as templates with a payload stapled on. A generator that produces obviously-seamed documents will
report a signal that does not exist in the wild.

### Phase 2 — measure

The probe computes, over the generated corpus:

| metric | definition | this is the answer to |
|---|---|---|
| **M1 localisation** | fraction of positives where the segment containing `injected_span` is the top-1 register outlier; also top-3 | does the seam exist and can we find it? |
| **M2 separation** | distribution of each document's max outlier score, positives vs. matched negatives; TPR at the threshold where FPR on matched negatives is 0 | is it a detector or a coin? |
| **M3 by carrier** | M1 and M2 broken out per carrier format | does it generalise past email? |
| **M4 by position** | M1 broken out per insertion position | does it only work on trailing payloads? |
| **M5 length floor** | M1 as a function of carrier byte length, bucketed | where does it stop working? Corpus p50 is 174 B |
| **M6 cost** | ms/MB for `DocumentMap::build` vs. `QuotingMap::build` | can Phase 4 afford it? |
| **M7 held-out** | M1 and M2 on the 36 hand-written fixtures, threshold frozen from generated data | did we fit our own generator? |

Reported per-slice, never as one aggregate — `corpus-analysis.md` Finding 1 is the standing reason.

**Exit:** the kill criteria in §6.

### Phase 3 — the honest write-up

Whatever the numbers say, they land in `docs/research/` and the negative result is as publishable as
the positive one. If it dies here it dies having cost two files and a corpus that `please-eval`
wants anyway.

### Phase 4 — only if §6 passes: make it a feature

Then, and only then, a `speckit` spec covering: merging the traversal into one pass (§2), a bounded
segment count, thresholds as rule-set calibration, a new detection class or a corroborating signal
on existing observations, and `--explain` output that names the segment and the deviating field. The
sixth-class argument in `specs/003` is the template for whether it is a class at all.

**The judge tier is the other consumer, and possibly the better one.** `docs/limits.md` records that
`span_relation_to_document` is carrying more of feature 004 than intended (12/12 agreement, against
14/20 for `span_role`, with every disagreement running the same way). A `DocumentMap` gives the
judge the container explicitly — *here is the segment, here is its siblings' register, here is the
delta* — instead of asking it to infer the container from a document and an excerpt. That may be
worth more than a new structural class, and it should be measured in the same probe.

---

## 5. Three ways this experiment could lie to us

Named in advance, with the mitigation, because each of them would produce an encouraging number.

1. **The generator's seams are our seams.** We would be generating the discontinuities we already
   believe in. Mitigation: M7 holds out the hand-written fixtures entirely, and BIPIA/InjecAgent
   samples are kept as a second held-out set once `please-eval` can fetch them. A strong M2 with a
   weak M7 means we measured our own imagination.
2. **The matched negative is too easy.** Carrier-without-payload is a *perfect* negative, which
   makes M2 flattering. The false positive that actually matters is security prose *about* payloads,
   which has a payload and no seam. Mitigation: the false-positive slice must include the benign
   security-prose fixtures and OR-Bench, not only matched carriers.
3. **The split shares carrier sources.** This is precisely the critique levelled at TaskTracker's
   evaluation — holding out attack types while sharing benign text between splits. Mitigation: split
   by **carrier**, not by row. A carrier appearing in the threshold-selection set may not appear in
   the reporting set.

---

## 6. Kill criteria, agreed in advance

Abandon, rather than tune, if any of these holds at Phase 2:

* **M1 top-3 localisation below 60%** on the generated corpus. The seam either exists and is findable
  or it does not; a signal that cannot rank the injected segment into the top three of its own
  document is not going to survive a real carrier.
* **M2 gives TPR below 25% at zero FPR** on the combined negative set including security prose. Below
  that it is not a detector, and `docs/limits.md` already has enough entries reading "accepted, with
  the false-negative rate unmeasured".
* **M3 shows it works on one carrier format only.** A signal that fires on email and nothing else is
  a rule about email, and rules are data — write the rule instead of the tier.
* **M7 falls off a cliff relative to M2.** We fit the generator. The correct response is a better
  generator, not a tuned threshold, and that is a different (larger) decision to take deliberately.

Two things that are explicitly **not** kill criteria, so they do not get used as one later:

* A weak M4 on non-trailing positions. Position sensitivity is a finding, not a failure — BIPIA's own
  ablation says trailing is where the attacks are.
* A high M6. Cost is a Phase 4 engineering problem with a named remedy (§2). It is not evidence about
  whether the signal is real.

---

## 7. What a reader should take away

The cheap version is roughly two files and a corpus generator. It requires no dependency, no model,
no network, and no change to anything that currently ships. It produces a number that decides
whether the embedding tier in `indirect-structure.md` §4 is worth its 400 MB — and if the answer is
no, it produces the list of carriers that defeated it, which is the specification for what the model
would have to be good at.

That is the whole argument for doing it in this order.
