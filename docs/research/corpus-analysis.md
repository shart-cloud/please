# Corpus analysis — Necent/llm-jailbreak-prompt-injection-dataset

Measured 2026-08-15 against revision `4edfb5aeaafe58c9bf489a478a42188f239d7c1e`
via DuckDB over the Hub parquet conversion (`hf datasets sql`). No bulk download.

Access: gated (`gated: "auto"`), approved for HF user `jlgore`. 4 parquet shards,
411 MB source / ~1.01 GB used storage.

## Totals

| Metric | Value |
|---|---|
| Rows | 1,175,432 |
| `prompt_adversarial = 1` | 321,333 (27.3%) |
| `prompt_harmful = 1` | 480,991 (40.9%) |
| Adversarial **and not** harmful | 226,156 |
| Clean benign (both labels 0) | 468,285 (39.8%) |
| Distinct `source` | 41 |
| Distinct `language` | 39 |

Label semantics are orthogonal (WildGuard-style). For an injection firewall the
positive class is `prompt_adversarial`; `prompt_harmful` is content moderation
and is a separate, opt-in concern.

Usable binary task: **321,333 positive vs 468,285 clean negative.** Roughly
balanced, no synthetic negatives required.

## Finding 1 — one source is half the positive class

| source | rows | adversarial | harmful |
|---|---|---|---|
| jayavibhav-PI | 316,126 | 158,110 | 0 |
| WildGuardMix | 84,457 | 41,721 | 44,798 |
| ALERT | 44,750 | 30,718 | 44,750 |
| LLMail-Inject | 28,174 | 28,174 | 0 |
| WildJailbreak | 65,273 | 14,975 | 65,273 |
| SPML | 16,012 | 12,542 | 0 |
| ObfuscationAugmenter | 9,855 | 9,855 | 9,855 |
| JailBreakV-28k | 10,185 | 8,640 | 10,185 |
| llama3-jailbreaks | 29,906 | 5,447 | 9,463 |
| RedBench | 26,757 | 3,033 | 23,100 |
| safe-guard-PI | 9,471 | 2,556 | 0 |
| TensorTrust | 1,346 | 1,346 | 0 |
| InjecAgent | 1,054 | 1,054 | 0 |
| Gandalf-Ignore | 887 | 887 | 0 |
| InTheWild-Jailbreaks | 9,392 | 785 | 785 |
| SafeMTData | 1,420 | 600 | 1,420 |
| deepset-prompt-injections | 661 | 263 | 0 |
| BIPIA | 450 | 250 | 0 |
| ToolEmu | 144 | 144 | 0 |
| ArtPrompt | 41 | 41 | 41 |

`jayavibhav-PI` supplies 158,110 / 321,333 = **49.2%** of all adversarial rows,
and 158,016 of the clean-benign rows besides. A single aggregate score over this
corpus is substantially a score on one source.

**Consequence:** metrics MUST be reported per-source and the eval MUST stratify
by source. A headline aggregate number is not a defensible claim.

## Finding 2 — indirect injection is 9% of the positive class

The threat this project exists to stop is *indirect* injection: hostile text
arriving inside a skill file, a tool result, a fetched page, an MCP tool
description. The sources that actually model that:

| source | adversarial rows | kind |
|---|---|---|
| LLMail-Inject | 28,174 | email-borne indirect |
| InjecAgent | 1,054 | agentic tool-output |
| BIPIA | 250 | benchmark, indirect |
| ToolEmu | 144 | agentic tool-output |
| **total** | **29,622** | **9.2% of adversarial** |

Excluding LLMail-Inject, the agentic subset is **1,448 rows (0.45%)**.

**Consequence:** this corpus is predominantly *direct* user-turn jailbreak text.
It is a legitimate primary corpus, but it cannot on its own validate the
artifact-scanning use case (`SKILL.md`, tool output, MCP descriptions). A small
hand-authored indirect corpus is required to cover that, and must be kept
separate from the public-corpus metrics rather than blended into them.

## Finding 3 — `attack_technique` is unlabelled for 94.8% of positives

| attack_technique | rows |
|---|---|
| *(empty)* | 304,685 |
| circuit_breaker | 4,000 |
| leetspeak | 1,971 |
| base64 | 1,971 |
| hex | 1,971 |
| reversed | 1,971 |
| rot13 | 1,971 |
| hijacking | 776 |
| extraction | 570 |
| human_mt | 291 |
| pair | 264 |
| prefill | 197 |
| autodan | 195 |
| best_of_n | 195 |
| many_shot | 160 |
| gcg | 100 |
| simple_adaptive | 45 |

Only 16,648 positives (5.2%) carry a technique label.

**Consequence:** per-technique reporting is only honest on that 5.2% slice.
Usefully, the obfuscation family — base64 / hex / rot13 / reversed / leetspeak,
1,971 each, 9,855 total — is exactly what a decode-then-rescan detector targets,
so it forms a precise unit-level eval slice for that one detector. Report it as
such; do not extrapolate it to the corpus.

## Finding 4 — zero non-English adversarial examples

```
SELECT language, count(*) FROM ... WHERE prompt_adversarial = 1 GROUP BY language
→ en  321,333
```

All 321,333 adversarial rows are `language = 'en'`. The 39 languages live
entirely in the benign and harmful-only rows (PolyglotToxicityPrompts 48,000
benign; Lumees-Multilingual 26,024; LinguaSafe 5,253).

**Consequence:** this is an asymmetry that flatters a detector. There are ~79K
non-English *negatives* and zero non-English *positives*, so a detector can post
an excellent multilingual false-positive rate while having no evidence
whatsoever of multilingual true-positive rate. Multilingual detection MUST be
declared an explicit known gap, not inferred from these metrics.

## Finding 5 — hard negatives are already present

Clean-benign composition:

| source | rows |
|---|---|
| jayavibhav-PI | 158,016 |
| OR-Bench | 79,041 |
| RealToxicityPrompts | 66,827 |
| PolyglotToxicityPrompts | 48,000 |
| Lumees-Multilingual | 26,024 |
| llama3-jailbreaks | 20,443 |
| WildGuardMix | 18,829 |
| Aegis-2.0 | 13,022 |
| ToxicChat | 9,139 |
| InTheWild-Jailbreaks | 8,607 |
| safe-guard-PI | 6,915 |
| LinguaSafe | 5,253 |

OR-Bench (79,041) is a purpose-built over-refusal control set — seemingly-unsafe
but actually-benign prompts. It is the natural false-positive gate corpus.

Still missing, and to be authored: **technical security prose**. A threat model,
a CVE writeup, or a document *about* prompt injection contains injection strings
as subject matter. No source here covers that, and it is the false-positive class
most likely to make a developer disable the firewall.

## Finding 6 — input sizes demand linear-time scanning

| p50 | p95 | p99 | max |
|---|---|---|---|
| 174 B | 1,372 B | 3,124 B | 82,300 B |

An 82 KB single prompt exists in the corpus, and real scan targets (a `SKILL.md`,
a fetched page, a tool result) are larger still.

**Consequence:** a security tool must not be a denial-of-service vector against
the host it protects. Detectors MUST be linear-time — no backtracking regex — and
inputs MUST have an explicit configured size cap with a defined
over-cap verdict. Throughput budgets should be expressed per KB, not per prompt.

## Licensing and redistribution

MIT covers the aggregation code only; each of the 41 sources retains its original
licence. The gate requires agreeing to respect those upstream licences.

**Consequence:** prompt text MUST NOT be vendored into this repository. The eval
fetches and caches locally, and the repo carries only a manifest — row id,
labels, source, and a SHA-256 of the prompt — which makes runs reproducible and
verifiable without redistributing the corpus.

## Reproducing these numbers

```sh
hf auth whoami   # gated access required
hf datasets sql "SELECT count(*), sum(prompt_adversarial), sum(prompt_harmful) \
  FROM 'hf://datasets/Necent/llm-jailbreak-prompt-injection-dataset/**/*.parquet'"
```
