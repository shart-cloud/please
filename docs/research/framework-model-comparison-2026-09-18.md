# PLEASE framework: Candle GLiNER2 and Jev — September 18, 2026

All 6,000 public and 600 contextual GLiNER2 rows ran through the native PLEASE bench using Rust/Candle. Jev results are the separate frozen live capture, imported through the same framework without extra API calls. Different models use different recipes and score gates; this is an exploratory comparison, not calibrated deployment accuracy.

| Public system | Attack recall | Benign false positives | Abstained | Failed |
|---|---:|---:|---:|---:|
| candle | 1976/3000 (65.9%) | 180/3000 (6.0%) | 347 | 0 |
| jev | 1854/3000 (61.8%) | 4/3000 (0.1%) | 643 | 19 |
| structural | 745/3000 (24.8%) | 11/3000 (0.4%) | 0 | 17 |

All-row recall includes abstentions and failures as misses. False-positive rates require reading coverage alongside them. Detailed native reports retain every stratum and row.

## Public source breakdown

| Source | Candle attack recall | Jev attack recall | Structural attack recall | Candle benign false positives |
|---|---:|---:|---:|---:|
| BIPIA | 94/250 (37.6%) | 59/250 (23.6%) | 1/250 (0.4%) | N/A |
| Gandalf-Ignore | 349/400 (87.2%) | 353/400 (88.2%) | 213/400 (53.2%) | N/A |
| InjecAgent | 400/400 (100.0%) | 400/400 (100.0%) | 171/400 (42.8%) | N/A |
| LLMail-Inject | 83/400 (20.8%) | 178/400 (44.5%) | 166/400 (41.5%) | N/A |
| LinguaSafe | N/A | N/A | N/A | 12/150 |
| Lumees-Multilingual | N/A | N/A | N/A | 6/150 |
| OR-Bench | N/A | N/A | N/A | 16/1000 |
| ObfuscationAugmenter | 181/400 (45.2%) | 181/400 (45.2%) | 23/400 (5.8%) | N/A |
| PolyglotToxicityPrompts | N/A | N/A | N/A | 10/150 |
| ToolEmu | 78/100 (78.0%) | 0/100 (0.0%) | 11/100 (11.0%) | N/A |
| WildGuardMix | N/A | N/A | N/A | 25/400 |
| deepset-prompt-injections | 128/250 (51.2%) | 135/250 (54.0%) | 40/250 (16.0%) | 6/350 |
| jayavibhav-PI | 306/400 (76.5%) | 253/400 (63.2%) | 25/400 (6.2%) | 84/400 |
| safe-guard-PI | 357/400 (89.2%) | 295/400 (73.8%) | 95/400 (23.8%) | 21/400 |

## Contextual regression

| True relation | Candle correct | Jev correct |
|---|---:|---:|
| aligned_instruction | 9/150 (6.0%) | 149/150 (99.3%) |
| conflicting_instruction | 108/150 (72.0%) | 138/150 (92.0%) |
| indeterminate | 60/150 (40.0%) | 108/150 (72.0%) |
| non_instruction | 36/150 (24.0%) | 1/150 (0.7%) |

The 600 contextual rows contain only 50 distinct candidate texts, 150 correlated groups and 15 workflow families. Correct indeterminate rows exclude input/runtime failures. Independent label review is pending; this is not research-H confirmation.

## Limits and implementation checks

Candle implements GLiNER2 single-label classification only. The pinned model and official GLiNER2 2.0.0 reference agree on all 18 numerical probes, including the 512-token boundary, and 128 additional Unicode tokenization probes. This validates tested implementation behavior, not model accuracy. The 0.7 score gate is uncalibrated. Inputs over 512 encoded tokens, including schema, abstain without truncation; reserved special tokens also abstain. These cap/marker failures remain in the reported denominators.

Candle public error/limit reasons: `{"encoded input exceeds token cap; no truncation": 171}`.
Candle contextual error/limit reasons: `{}`.

Language, upstream harmful labels, and length strata are retained separately in the JSON. There are no non-English positive cases; non-English controls measure false positives only. Harmful-labeled positives all come from ObfuscationAugmenter, so that stratum cannot establish general harmful-content performance.

CPU timing was collected while the two native model runs overlapped, so it is not an isolated throughput benchmark. No shipping model, threshold, or release authority changed. Public text stays in ignored cache. See the Jev scale report for language, harmful-label, source-selection and remote-provider limitations.

## Open the app results

```bash
.cache/framework-models-20260918/please-eval bench view --run .cache/framework-models-20260918/run-public
.cache/framework-models-20260918/please-eval bench view --run .cache/framework-models-20260918/run-contextual
```

Each run also contains a standalone `report.html`. Viewing verifies saved identities and performs no inference.
