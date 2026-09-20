# GLiNER2 + Jev paired error audit — September 19, 2026

Offline audit of the two completed September 18 public runs, joined case-by-case.
**No API calls, no inference, no weight downloads, no shipping default changed.** The
frozen runs were re-verified through `please-eval bench report` before use; both sides
share pack digest `d2979c50…`, so the 6,000-case join is exact on `case_id` and
`input_sha256`.

All 6,000 cases are exposed development evidence. Nothing here is a holdout, a
calibration, or a release gate. Every threshold below the shipping 0.7 gate is
*selected on data the models have already been measured against*.

## The decision rule reproduces exactly

Before comparing any operating point, the recorded decisions were re-derived from the
saved distributions: argmax over `{injection, benign, indeterminate}`, abstaining when
the argmax is `indeterminate` or the winning probability is below the gate.

| System | Rows with saved scores | Mismatches |
|---|---:|---:|
| GLiNER2 (Candle) | 5,829 | 0 |
| Jev | 5,981 | 0 |

One correction worth recording: **Jev's gate acts on the maximum probability, not on the
`confidence` field it also returns.** Gating on `confidence` mis-predicts 298 rows. Rows
without saved scores (171 GLiNER2 input-cap, 19 Jev provider-contract) are excluded from
reconstruction and never imputed; they remain misses in every denominator below.

## Every non-detection, by mechanism

| Mechanism | GLiNER2 attacks | GLiNER2 benign | Jev attacks | Jev benign |
|---|---:|---:|---:|---:|
| flagged injection | 1976 | 180 | 1854 | 4 |
| called benign (model choice) | 886 | 2611 | 526 | 2954 |
| abstained: score gate | 47 | 129 | 602 | 41 |
| abstained: input cap | 91 | 80 | — | — |
| failed: provider contract | — | — | 18 | 1 |

Jev's largest single loss is not a modelling error: **602 attacks (20.1%) are score-gate
abstentions**, versus 526 confident misses. GLiNER2's profile is the opposite — it decides
almost everything and is wrong more often.

## Paired detector table

| Cell | Attacks (n=3000) | Benign (n=3000) |
|---|---:|---:|
| both flag | 1498 | 3 |
| GLiNER2 only flags | 181 | 162 |
| Jev only flags | 302 | 1 |
| neither flags | 311 | 2585 |
| only GLiNER2 decided | 570 | 40 |
| only Jev decided | 88 | 207 |
| neither decided | 50 | 2 |

The models are genuinely complementary on attacks and almost disjoint on false alarms —
**they agree on only 3 of 3,000 benign rows.** That disjointness is what makes `OR`
expensive and `AND` cheap, and it is the single most important structural fact here.

By source, the complementarity is not uniform: Jev never flags any of the 100 ToolEmu
attacks (GLiNER2 catches 78), while Jev catches 127 LLMail-Inject attacks that GLiNER2
misses (GLiNER2 adds only 32 there).

## The errors are not calibration-fixable — for one model

Winning probability on wrong decisions:

| Band | GLiNER2 false alarms | GLiNER2 confident misses | Jev false alarms | Jev confident misses |
|---|---:|---:|---:|---:|
| [0.70, 0.90) | 13 | 30 | 4 | 220 |
| [0.90, 0.99) | 23 | 50 | 0 | 178 |
| [0.99, 0.999) | 19 | 46 | 0 | 38 |
| [0.999, 1.0] | **125** | **760** | 0 | 90 |

**69% of GLiNER2's false alarms and 86% of its confident misses sit above p>0.999.** Its
softmax is saturated, so its score carries almost no ranking information — which is
exactly why raising its gate from 0.7 to 0.999 removes only 55 of 180 false alarms while
also costing 108 detections. No threshold rescues GLiNER2.

Jev is the opposite: all four of its false alarms sit in the lowest band, and its misses
spread across bands. Its scores *do* rank, which is why its own gate is a real lever.

## Operating points

Denominators are always 3,000 attacks / 3,000 benign; abstentions and failures count as
misses.

| Configuration | Attack recall | Benign false alarms |
|---|---:|---:|
| Jev @0.7 (shipping) | 1854 (61.8%) | 4 (0.13%) |
| GLiNER2 @0.7 | 1976 (65.9%) | 180 (6.00%) |
| GLiNER2 @0.999 | 1868 (62.3%) | 125 (4.17%) |
| AND (Jev@0.7 & GLiNER2@0.7) | 1498 (49.9%) | 3 (0.10%) |
| OR (Jev@0.7 \| GLiNER2@0.999) | 2270 (75.7%) | 127 (4.23%) |
| Jev @0.6 | 1988 (66.3%) | 8 (0.27%) |
| Jev @0.5 | 2121 (70.7%) | 9 (0.30%) |
| **SEL: Jev@0.5, else GLiNER2@0.99 on Jev non-decisions** | **2172 (72.4%)** | **11 (0.37%)** |

### Recall at stated false-positive budgets

| FP budget | Best recall | Configuration |
|---:|---:|---|
| 0 | 1512 (50.4%) | Jev @0.9 |
| 4 | 1854 (61.8%) | Jev @0.7 |
| 10 | 2121 (70.7%) | Jev @0.5 |
| 20 | 2176 (72.5%) | SEL Jev@0.5 else GLiNER2@0.4 |
| 100 | 2176 (72.5%) | *(unchanged — nothing between 12 and 126 FP)* |
| 200 | 2482 (82.7%) | OR Jev@0.4 \| GLiNER2@0.4 |

The Pareto frontier is **owned by Jev's own gate up to ~2121 detections at 9 false
alarms**. GLiNER2 contributes nothing below that point. Then there is a cliff: buying more
than ~72.5% recall jumps the false-alarm cost from 12 to 126 — a tenfold increase for the
next 19 detections.

## The honest headline

> **Most of the apparent GLiNER2 advantage is reproducible by moving Jev's own score gate,
> at a fraction of the false-alarm cost.**

GLiNER2 @0.7 catches 1976 attacks for 180 false alarms. Jev @0.6 catches *more* (1988) for
**8**. Any future claim that a local model "adds detections" must be compared against the
free threshold move first, not against the shipping 0.7 gate.

**The initial ambition was not met.** No configuration improves on Jev's 1854 detections
while holding its 4 false alarms: at a budget of ≤4, the best available configuration is
exactly the shipping one. Recall gains on this evidence cost false alarms, always.

## Where GLiNER2 does earn a role

The only configuration in which GLiNER2 is not simply dominated is **coverage repair**:
let Jev decide wherever it decides, and consult GLiNER2 *only* on rows where Jev returned
no decision. Against a `Jev@0.5` baseline this adds **+51 attacks for +2 false alarms**,
spread across eight sources rather than concentrated in one.

Notably, **11 of those 51 come from repairing Jev provider-contract failures** (18 invalid
distributions, 1 inconsistent choice) — a robustness gain that does not depend on GLiNER2
being a better classifier at all, only on it being independently available.

## Cascade ceilings, quantified before anyone builds one

- GLiNER2 fails to flag 1024 attacks at 0.7. **356 of those Jev alone would have caught.**
  A cascade that only forwards GLiNER2 positives to Jev discards all 356 permanently.
- Routing fraction: 65.9% of attacks and 6.0% of benign rows — a prefilter that forwards
  two thirds of attacks is not much of a filter.
- Jev has 526 confident misses. **Routing Jev's uncertainty cannot recover any of them**,
  by construction; they are not uncertain. GLiNER2 flags 181, reachable only by an OR or
  an override — both of which import GLiNER2's false-alarm burden.

## False-alarm concentration

Of the 125 GLiNER2 false alarms surviving a 0.999 gate, 64 are `jayavibhav-PI` (16.0% of
that source's benign rows) — the same source where GLiNER2 gains the most attacks. That
pattern is consistent with GLiNER2 keying on surface features that this corpus's benign
and attack text share. It is a lead for label review, **not** a licence to tune on source
identity; no policy measured here uses a source id or an expected label.

## Addendum — the ordering signal is there, the probability destroys it

Added September 19 after the main audit, prompted by a question about fine-tuning.
The runs saved raw **logits**, not just probabilities, so the ranking quality of
GLiNER2's own score can be tested with no training and no inference.

Ranking attacks against benign rows by `z_injection - max(z_benign, z_indeterminate)`
instead of by the saturated max-probability:

| FP budget | Recall, max-probability | Recall, logit margin |
|---:|---:|---:|
| 0 | 0 (0.0%) | 158 (5.3%) |
| 4 | 0 (0.0%) | 562 (18.7%) |
| 9 | 0 (0.0%) | 896 (29.9%) |
| 20 | 0 (0.0%) | 1044 (34.8%) |
| 50 | 0 (0.0%) | 1428 (47.6%) |
| 100 | 1774 (59.1%) | 1774 (59.1%) |

AUC over scored rows rises from **0.8204 to 0.8899**. Recall denominators remain the full
3000; the 91 attack rows with no saved score (input cap) stay misses and are excluded from
the curve only.

The max-probability column is not a rounding artifact — so many rows are pinned at exactly
1.0 that no threshold below 100 false positives separates anything at all. **The encoder's
features carry usable ordering information that the saturated softmax discards.**

Two consequences:

1. The earlier conclusion "no threshold rescues GLiNER2" was about the *shipped* score, and
   stands. But it should not be read as "the features are uninformative" — they are not.
2. This is now evidence-backed motivation for fine-tuning with label smoothing or soft
   targets, since the failure is a calibration/scale pathology rather than an absence of
   signal. It is not evidence that GLiNER2 can replace Jev: at a 9-false-alarm budget,
   margin-ranked GLiNER2 reaches 29.9% where Jev@0.5 reaches 70.7%.

The defensible near-term use remains the coverage-repair lane, where a better-ordered score
should let the repair operating point be chosen far more precisely than `p>=0.99` allowed.

Reproduce: `python3 crates/eval/scripts/pairing_audit/margin.py`

## Limits

- Exposed development evidence throughout; no holdout, no calibration, no release gate.
- Sub-0.7 gates are selected on this data and are not validated operating points.
- Four false alarms is far too small a count to establish any deployment rate.
- Harmful-labelled positives come from one source; there are no non-English positives, so
  multilingual rows establish false-positive behaviour only.
- GLiNER2 probabilities are uncalibrated and saturated; they are not reliability estimates.
- Source counts are correlated within families and should not be treated as independent.

## Suggested next arms (not started, not authorised)

1. **Binary artifact schema for GLiNER2.** The explicit `indeterminate` class competes
   inside the softmax and 176 gate abstentions plus the saturation pattern suggest it is
   distorting the other two logits. Requires fresh inference; label text changes inputs.
2. **Coverage-repair integration only**, behind an evaluation configuration — the one role
   the evidence supports, and the provider-failure repair is its most defensible part.
3. **Re-baseline every future arm against a Jev threshold sweep**, so that a model's
   contribution is measured net of the free lever.
4. Long-input handling for the 171 capped cases, only if an audit of those cases supports
   it; keep an unchanged cap baseline.

## Reproduction

```bash
cd /home/jg/git/bee-swarm
python3 crates/eval/scripts/pairing_audit/extract.py       # join, prints paired sha256
python3 crates/eval/scripts/pairing_audit/faithfulness.py  # decision-rule reconstruction
python3 crates/eval/scripts/pairing_audit/audit.py         # phase 1
python3 crates/eval/scripts/pairing_audit/phase2.py        # phase 2
python3 crates/eval/scripts/pairing_audit/phase3.py        # Pareto frontier / budgets
python3 crates/eval/scripts/pairing_audit/phase4.py        # error confidence
python3 crates/eval/scripts/pairing_audit/summarize.py     # summary.json
```

Evidence: `.cache/pairing-audit-20260919/`. Counts in
[the companion JSON](gliner2-jev-pairing-audit-2026-09-19.json). Corpus text stays in
ignored cache; no case text is reproduced here or in the JSON.
