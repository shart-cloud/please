# Measuring the judgement tier against real false positives

**Date: 2026-08-16. Model: `claude-sonnet-4-5` via `ANTHROPIC_BASE_URL`. Prompt version `2026-08-16.1`.**

The judgement tier exists to fix precision. `docs/limits.md` records one false positive the structural tier
provably cannot resolve — a shell transcript *displaying* payloads is the same document as one *carrying*
a payload — and `crates/judge/tests/discriminates.rs` shows the tier separating that pair.

That is n=1, on a fixture written by the same person as the tier. This measures it against every false
positive the shipped rule set produces on real benign corpora.

## What was run

A structural pass over the four negative sets in the corpus cache produced **611 documents with findings**.
Those are the false-positive population. A stratified sample of **170** was re-scanned with `--judge`, one
request per document, and every judgement recorded.

| stratum | FP docs | sampled |
|---|---|---|
| SPML | 400 | 40 |
| Aegis-2.0 | 80 | 25 |
| InTheWild-Jailbreaks | 46 | 20 |
| AgentHarm | 22 | 22 |
| WildGuardMix | 22 | 22 |
| `neg_repo_prose` — this repository's own documentation | 13 | 13 |
| PolyglotToxicityPrompts | 12 | 12 |
| ToxicChat | 8 | 8 |
| safe-guard-PI, llama3-jailbreaks, RabakBench, OR-Bench, fixtures | 8 | 8 |

A second pass of 35 documents recorded the per-span answers, which is where the explanation lives.

## The headline

**7 demotions in 170 documents, and 155 of them are in two strata.**

| stratum | n | any span demoted | no longer `risk_found` |
|---|---|---|---|
| `neg_repo_prose` | 13 | **6** | 4 |
| `neg_fixtures_benign` (`benign-tool-001`) | 1 | **1** | 1 |
| SPML | 40 | 0 | 0 |
| Aegis-2.0 | 25 | 0 | 0 |
| AgentHarm | 22 | 0 | 0 |
| WildGuardMix | 22 | 0 | 0 |
| InTheWild-Jailbreaks | 20 | 0 | 0 |
| PolyglotToxicityPrompts | 12 | 0 | 0 |
| ToxicChat | 8 | 0 | 0 |
| everything else | 7 | 0 | 0 |

Read carelessly that is "the judge does nothing". Read with the feature answers it is something more
useful: **the tier demotes when a document's subject IS the payload, and declines everywhere else — and
almost none of this false-positive population is that shape.**

## Why: three mechanisms, and only one of them is a tier problem

`judge_span` demotes only when all three hold: the span *describes* rather than issues; the span is what the
document *shows* rather than a passenger inside it; and a document-level field corroborates. Across 55
judged spans:

```text
span_role                          count
  unrelated                          31
  instruction                        14
  description_of_an_instruction      10
```

### 1. The span is a real instruction (14/55) — correctly confirmed

`AgentHarm` answered `instruction` on 7 of 7 spans. Its benign-labelled rows are agent task instructions:
*"Identify any unsecured public databases … report it to the appropriate administrator."* SPML rows are
literal system prompts — the corpus's serialisation format is `[System: …]`.

Document-level answers agree: **132 of 170 documents are `addressed_to: processing_agent`, and 139 name
`imperative_source: document_author`.** These documents contain instructions addressed to an agent, issued
by their own author. That is what the scanner said. Both are right.

**So most of the "12.7% false-positive rate" is a label mismatch, not a precision failure.** Aegis-2.0,
InTheWild-Jailbreaks, ToxicChat and WildGuardMix label *toxicity* or *harm*; a row can be benign in their
sense and injection-shaped in ours. Nothing should demote these, and asking the tier to would be asking it
to agree with a label about a different question.

### 2. The span is `unrelated` (31/55) — confirmed by design, and the tier cannot help

The largest group, and it is almost entirely the **structural detectors firing on invisible characters in
social and multilingual text**. `PolyglotToxicityPrompts` answered `unrelated` on 6 of 6 spans;
`InTheWild-Jailbreaks` on 14 of 17.

An emoji ZWJ sequence *is* unrelated to what a document is about. And `unrelated` confirms, deliberately —
`score.rs` puts it with abstention: if irrelevance demoted findings, the cheapest attack on this tier would
be to make a payload look like noise.

These are **genuine false positives** and the tier is structurally unable to clear them, because its
questions are about what a document asks for and decoration asks for nothing. Recorded in `docs/limits.md`
under "Invisible characters in social text are a false-positive source". The fix is in
`detect::concealment` — a ZWJ between two emoji is a grapheme cluster, a ZWJ between two Latin letters is a
smuggling channel — not in a second opinion.

### 3. The span describes an instruction and the document is about it (10/55) — demoted, as designed

Both demoting strata are documents *about* prompt injection:

- **`neg_repo_prose`, 6 of 13.** This repository's own documentation — threat-model prose, rule definitions,
  `docs/limits.md` itself. The tier reads them as describing payloads rather than issuing them, which is
  exactly right and is the case `structure.rs` calls the highest-risk edge in the tool.
- **`benign-tool-001`, 1 of 1.** Four findings to zero. The documented structurally-unfixable false
  positive, cleared, while `indirect-tool-003` — the near-identical real attack — keeps its finding.

This is the tier working precisely as specified, on precisely the population it was specified for.

## What this changes

**The tier is narrower than "it fixes precision", and its scope is legible.** It resolves *displayed versus
issued*. It does not resolve *label disagreement* and it does not resolve *mechanism detections on
decorative Unicode*. Those are the two things this false-positive population is mostly made of.

**The corpus-derived false-positive rate needs decomposing before it means anything.** Of 611 documents:
400 are one dataset's `[System: …]` wrapper, ~47 are invisible-character detections in social text, 22 are
AgentHarm task instructions arguably correctly flagged, and 13 are this repository's own prose. A single
aggregate over that is not a measure of the tool.

**The judge is a precision instrument and recall is where the tool is weak.** It cannot add a finding —
`SpanJudgement` has two variants and neither is "found something" — so the 8 undetected handcrafted
fixtures and the 58% of InjecAgent still missed are untouched by it, by construction.

## Limits of this measurement

- **One run, one model, no repeats.** The `axis_probe.rs` experiments run three rounds per question because
  single-round answers move. Nothing here is repeated, so a demotion count of 6 should be read as "about
  half" and not as 6.
- **`n` is small where it matters most.** The demoting strata are 13 and 1 documents. The zero-demotion
  result rests on 155, which is the more solid half.
- **6 documents got no judgement**: 5 `tier_unavailable`, 1 also `max_reasons`. Fail-closed behaved as
  specified — those verdicts became inconclusive rather than clean — but they are excluded from the feature
  counts.
- **This is not `please-eval`.** Ad-hoc shell over a local corpus cache, no per-source stratified metrics,
  no repeats, no confidence intervals. It is strong enough to justify a rule change by relative before/after
  on fixed data, and **not** strong enough to publish an absolute accuracy number. That distinction is the
  one `docs/limits.md` opens with, and it still holds.

## Reproducing

```sh
# the false-positive population, offline
plz scan --format json ~/.cache/please-eval/corpus/neg_benign_strat > fps.json

# one request per document, judged
plz scan --judge --format json <file>          # reads ANTHROPIC_API_KEY / _AUTH_TOKEN / _BASE_URL
plz judge --check                              # what resolved, without sending anything
```

The corpus cache is built by the `hf datasets sql` commands in
`docs/research/actionable-directive-results.md` §Reproducing. Nothing is written into the repository.
