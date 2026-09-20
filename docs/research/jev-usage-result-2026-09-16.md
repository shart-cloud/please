# Jev usage-pattern experiment

204 cases screened under four fresh API recipes and one decoder-only arm sharing responses. All questions, inputs, labels, thresholds and selection gates were frozen before this round. This is same-author development evidence; delivery copies and reused task templates are correlated.

## Same 120 context-controlled cases

| Recipe | Macro recall | Analysis recognized | Conflicts detected | Coverage | Wrong determinate / missing | Complete context groups |
|---|---:|---:|---:|---:|---:|---:|
| C: Fresh previous focused recipe | 65.6% | 15/30 | 20/30 | 63/90 | 0/30 | 14/30 |
| P: C with component-scoped validation (shared capture) | 65.6% | 15/30 | 20/30 | 63/90 | 0/30 | 14/30 |
| R: Rewritten questions, model routes | 75.6% | 14/30 | 27/30 | 71/90 | 0/30 | 14/30 |
| H: Caller routes, concise question | 85.6% | 18/30 | 30/30 | 78/90 | 0/30 | 18/30 |
| X: Caller routes, contrastive examples | 81.1% | 14/30 | 30/30 | 76/90 | 0/30 | 14/30 |

The previous focused recipe scored 66.7% on these exact 120 cases in the earlier run. C is a contemporaneous rerun; P uses exactly the same raw responses as C. The current shipping four-way CLI recipe is a different recipe and was not freshly rerun in this round.

R asks about workflow modality, active redirection and operational authorization. H/X receive an explicit caller-owned workflow mode and ask only the relevant question; analysis omits execution permissions. X adds contrastive examples. H/X are caller-assisted systems; their gains are not model-only improvements with identical inputs. None of these recipes supplies the expected label or a permission decision in code.

## Supplementary regressions

These 84 cases combine the prior 36 with 48 new rows: quoted attack discussion versus active redirection, exact action/resource matching, conflicting entries, out-of-scope operations, candidate authorization claims and mixed allowed/denied requests.

| Recipe | Analysis recognized | Conflicts detected | Aligned recognized | False reassurance | Wrong determinate / missing |
|---|---:|---:|---:|---:|---:|
| C | 18/30 | 32/39 | 0/3 | 2/39 | 0/12 |
| P | 18/30 | 32/39 | 0/3 | 2/39 | 0/12 |
| R | 19/30 | 36/39 | 3/3 | 0/39 | 0/12 |
| H | 23/30 | 39/39 | 3/3 | 0/39 | 0/12 |
| X | 19/30 | 39/39 | 3/3 | 0/39 | 0/12 |

New 48 and old 36 results are also broken out separately by family and delivery in summary.json. These are targeted regressions authored by the same evaluator, not independently reviewed or blinded data.

## Frozen decision

| Recipe | Eligible | Failed gates |
|---|---|---|
| C | False | macro_recall, analysis_recall, conflict_recall, coverage, no_false_reassurance, supplementary_recall, supplementary_material_false_conflicts |
| P | False | macro_recall, analysis_recall, conflict_recall, coverage, no_false_reassurance, supplementary_recall, supplementary_material_false_conflicts |
| R | False | macro_recall, analysis_recall, coverage, supplementary_recall |
| H | False | analysis_recall, coverage, supplementary_recall |
| X | False | macro_recall, analysis_recall, coverage, supplementary_recall, supplementary_material_false_conflicts |

No candidate passed every screening gate. The declared rule therefore stopped before the 600-case confirmation; no prompt or threshold was changed after seeing results.

## What improved and what remains

The concise caller-routed recipe H was the strongest on the original comparison slice: 85.6% macro recall versus 65.6% for fresh C. Across the full screen, H detected 69/69 conflicts, correctly handled 32/33 allowed requests, and made no determinate decision on any of 42 missing/contradictory-permission cases.

Its remaining weakness was analysis-only material: 41/60 recognized, 17 abstentions and 2 false conflicts. Its native redirection answers were {'no': 51, 'yes': 9}; confidence gating explains some losses but the native choices also contain errors. Lowering thresholds without new calibration would not be justified by this run.

H got all 48 newly authored rows correct, including the quoted-discussion pairs and exact permission controls. That narrow, same-author set has repeated delivery forms; the harder prior fixtures are why the combined screen still fails. Additional examples in X worsened analysis recognition and did not improve conflict detection. The decoder-only P change produced no gain on these captures.

H used 55.1% fewer recorded input-plus-output tokens than C for the same 204 requests. Median request time remained about 450 ms for both; this is not a measured dollar saving or a repeated latency result. The useful integration direction is explicit caller-owned modality with a focused question and relevant context. The experiment does not isolate which part of that combined recipe caused the improvement.

## Decoder and failure audit

Component-scoped validation changed 0 predictions between C and P; case-by-case outcomes are in the JSON. This isolates that decoder change on identical responses. Numeric probabilities were never normalized. Invalid required components still abstain, and global envelope errors reject the whole response.

| Recipe | API requests | Global errors | Invalid components retained | Median ms | p95 ms | Input tokens | Output tokens |
|---|---:|---:|---:|---:|---:|---:|---:|
| C | 204 | 4 | 0 | 450.6 | 562.6 | 264134 | 28393 |
| P | 0 | 0 | 4 | shared | shared | 0 | 0 |
| R | 204 | 0 | 3 | 456.6 | 566.8 | 201302 | 23847 |
| H | 204 | 0 | 1 | 453.2 | 540.5 | 122906 | 8483 |
| X | 204 | 0 | 1 | 450.4 | 532.3 | 189338 | 8481 |

Total API attempts: 816/1,500. Returned models: {'jev-1.13.0': 812}. Recorded token usage: {'input_tokens': 777680, 'output_tokens': 69204}. No automatic retries. Dollar pricing is unknown. Usage from unreadable responses can be missing. P shares C usage, and is not counted twice.

Native replay verified: {'screen': 1020}. Capture hashes bind exact candidates, contexts and responses; native replay overhead is not inference latency. API timings include process startup, network and provider time, including failed attempts. This is one interleaved pass, not a repeated performance guarantee.

Fourteen offline checks passed for label independence, exact input binding, routing, partial validation, thresholds, missing components and selection. Saved output and decoded responses passed the credential-pattern audit. A provenance-spelling mismatch in preparation was corrected before any API call; the failed preflight is preserved separately.

## Scope and reproduction

The installed plz clap / plz jev commands and shipping enforcement were not changed. A higher development score is a promising integration direction, not evidence of deployment readiness. Independent label review, fresh workflow families and repeated trials remain necessary before promotion.

Frozen plan: docs/research/jev-usage-plan-2026-09-16.md. Source: crates/eval/scripts/jev_usage/. Evidence: .cache/jev-usage-20260916/. Re-run preparation only into a new output directory; never overwrite a recorded experiment.

Official Choice guidance: https://docs.typesafe.ai/primitives/choice . It documents independently evaluated questions and application-side use of relevant answers. Component-scoped handling of malformed answers is this experiment's policy.
