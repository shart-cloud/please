# Declared limits

What PLEASE does not do, and why. This document exists because the constitution requires evaluation
gaps to be stated explicitly alongside the metrics rather than left for a reader to infer — and because
a security tool whose limits you discover in production has already cost you something.

Read this before trusting a clean verdict.

## Accuracy is fixture-verified, not corpus-measured

**Status: open until the evaluation harness ships.**

Feature 001 verifies detection against curated fixtures: at least one positive per detection class, and
at least 200 hard negatives including technical security prose. It does **not** measure performance
against real attack corpora.

This means the tool can pass every success criterion it sets itself while its real-world accuracy
remains unknown. Fixtures bound the risk — they catch regressions and prove the mechanisms work — but
they are chosen by the same people who wrote the detectors, which is exactly the bias a real corpus
exists to break.

**No accuracy claim about PLEASE may be published until `please-eval` exists.** Not a percentage, not a
comparison, not a "catches most". This is recorded in the constitution and in four planning artifacts
because it is the single easiest thing to accidentally overstate.

## Multilingual detection is unmeasured, not supported

**Status: structural gap in available data.**

The primary evaluation corpus contains **zero** non-English attack examples — all 321,333 adversarial
rows are English — while carrying roughly 79,000 non-English benign rows.

That asymmetry flatters a detector in a specific and dangerous way: it can post an excellent
multilingual *false-positive* rate while having no evidence whatsoever about multilingual *detection*.
A tool reporting per-language metrics from this corpus would look good at exactly the thing it has not
been tested on.

So: PLEASE makes **no multilingual detection claim.** Its confusable analysis (FR-010) exists partly to
avoid the opposite failure — mistaking ordinary non-English prose for an evasion attempt, which would
actively harm non-English users. Closing the detection gap needs a corpus that does not yet exist.

## The structural tier recognises form, not intent

**Status: inherent to the tier; addressed by later tiers.**

Detection is pattern- and structure-based. It recognises the shape of known payload techniques —
override phrasing, concealment, encoding, boundary forgery, solicitation — not the meaning of text.

A novel phrasing that no rule anticipates will pass. An attacker who reads `rules/builtin.toml` knows
exactly what is checked. This is not a defect to be fixed within this tier; it is what the tier is, and
the model-backed and judgement tiers exist because of it.

## Quoted payloads can suppress detection

**Status: accepted false negative, unquantified.**

To avoid flagging documents that *discuss* prompt injection — threat models, advisories, rule
definitions, this repository's own specification — matches inside quoting contexts (fenced code, inline
code, block quotes, quoted strings, spans following attributive markers) are suppressed by default.

An attacker can therefore wrap a live payload in a code fence and suppress it.

The trade is deliberate. Without this suppression the tool flags security documentation, which makes it
unusable by the people most likely to evaluate it — and a firewall that gets switched off protects
nothing. `--no-suppress-in-quotes` disables the behaviour for callers who prefer the noise.

**The false-negative rate this costs has not been measured.** It cannot be, without the evaluation
harness. Stating it as "accepted" is honest only as far as that; do not read it as "small".

## Risk band boundaries are provisional

**Status: uncalibrated pending corpus metrics.**

The mapping from score to risk band (`low`/`medium`/`high`/`critical`) is currently chosen, not derived.
The default threshold is `high`, so every block/allow decision rests on those constants.

They will move when calibration happens. Fixture-era values are recorded alongside the metrics so a
recalibration reads as a visible diff rather than a number that quietly changed meaning.

## Indirect injection is under-covered by public data

**Status: partially mitigated by authored fixtures.**

The threat this tool exists to stop is largely *indirect*: hostile text arriving inside a skill file, a
tool result, a fetched page, an MCP tool description. In the primary corpus, indirect injection is
about 9% of adversarial rows — and under 0.5% if email-borne samples are excluded.

Public data is therefore weakest exactly where the product is aimed. Purpose-authored fixtures cover
the artifact-scanning case, and their metrics are reported **separately** from public-corpus metrics
rather than blended into them, because blending would let a strong result on direct jailbreaks conceal a
weak one on the case that matters.

## Scope: this is not a content moderator

**Status: deliberate scope boundary.**

PLEASE judges whether text attacks the agent reading it. It does not judge whether the subject matter is
harmful, offensive, or unsafe.

Those are different problems with different corpora and different consumers, and conflating them makes
both sets of metrics meaningless. Harmful-content detection may ship as an opt-in tier that **reports
and never blocks** by default. If you need moderation, use a moderation tool.
