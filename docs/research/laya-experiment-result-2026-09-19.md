# Laya vs Jev: measured development screen — 2026-09-19

Two pinned Laya checkpoints were evaluated locally on 1,200 public cases (600 attacks, 600 benign) and 600 contextual rows, with matched-question and compact-question arms. Jev uses the matched September 18 captures; no new API call was made. Both Laya models ran on the RTX 3050 Ti Laptop GPU using the upstream CUDA autocast path. This is exploratory development evidence, not a deployment claim.

## Public attack detection

| System | Attacks detected / 600 | Benign false alarms / 600 | Decided / 1200 | Input/runtime gaps |
|---|---:|---:|---:|---:|
| jev | 384 | 0 | 1074 | 6 |
| english-exact | 109 | 6 | 159 | 67 |
| typed-exact | 8 | 1 | 9 | 18 |
| english-full | 175 | 10 | 480 | 46 |
| typed-full | 12 | 1 | 14 | 15 |

Ungated native choices (diagnostic only; no threshold selected):

| System | Native attacks / 600 | Native benign false alarms / 600 |
|---|---:|---:|
| jev | 446 | 1 |
| english-exact | 335 | 41 |
| typed-exact | 343 | 41 |
| english-full | 385 | 58 |
| typed-full | 339 | 37 |

## Caller-context advice

| System | Macro recall | Aligned / 150 | Conflict / 150 | Analysis material / 150 | Unknown / 150 | False conflicts | Answerable coverage /450 |
|---|---:|---:|---:|---:|---:|---:|---:|
| jev | 66.0% | 149 | 138 | 1 | 108 | 99 | 397 |
| english-exact | 25.8% | 2 | 0 | 3 | 150 | 0 | 6 |
| typed-exact | 25.0% | 0 | 0 | 0 | 150 | 0 | 0 |
| english-full | 35.5% | 0 | 0 | 67 | 146 | 0 | 67 |
| typed-full | 25.0% | 0 | 0 | 0 | 150 | 0 | 0 |

Exact = original Jev questions and state supplied to Laya. Full = frozen compact Laya questions with the same state. Laya uses top support >=0.7 and margin >=0.15; its entropy confidence is recorded but not gated. Historical Jev artifact decisions use their saved max-support gate, while Jev contextual decisions additionally use their existing margin/confidence rules. Argmax and common-inference-subset diagnostics are retained in comparison.json.

## Predeclared screening decision

Public improvement required more detected attacks with no additional benign false alarms. Contextual improvement required higher macro recall without losing conflict/unknown recall or adding false conflicts. These descriptive gates do not substitute for reviewed calibration or statistical generalization.

public: english-exact FAIL, typed-exact FAIL, english-full FAIL, typed-full FAIL
contextual: english-exact FAIL, typed-exact FAIL, english-full FAIL, typed-full FAIL

## Measured timing

| System | Surface | Median whole decision, ms | Median local forward call, ms |
|---|---|---:|---:|
| jev | public | 484.2 | N/A: historical API |
| english-exact | public | 63.5 | 60.4 |
| typed-exact | public | 92.9 | 88.6 |
| english-full | public | 208.6 | 205.3 |
| typed-full | public | 226.7 | 221.3 |
| jev | contextual | 347.7 | N/A: historical API |
| english-exact | contextual | 263.9 | 259.5 |
| typed-exact | contextual | 263.6 | 259.2 |
| english-full | contextual | 230.4 | 226.5 |
| typed-full | contextual | 232.0 | 227.8 |

Timing excludes model loading and refused inputs. Local whole-decision timing includes tokenization/preflight; GPU calls were synchronized. Jev timings are historical end-to-end API measurements, not replay timings and not a same-day hardware comparison. Load times remain in native stderr/preflight captures. Shared-machine contention is uncontrolled.

## Public source breakdown

| Source | System | Attack recall | Benign false alarms |
|---|---|---:|---:|
| BIPIA | jev | 10/50 | N/A |
| Gandalf-Ignore | jev | 71/80 | N/A |
| InjecAgent | jev | 80/80 | N/A |
| LLMail-Inject | jev | 46/80 | N/A |
| LinguaSafe | jev | N/A | 0/30 |
| Lumees-Multilingual | jev | N/A | 0/30 |
| OR-Bench | jev | N/A | 0/200 |
| ObfuscationAugmenter | jev | 35/80 | N/A |
| PolyglotToxicityPrompts | jev | N/A | 0/30 |
| ToolEmu | jev | 0/20 | N/A |
| WildGuardMix | jev | N/A | 0/80 |
| deepset-prompt-injections | jev | 24/50 | 0/70 |
| jayavibhav-PI | jev | 58/80 | 0/80 |
| safe-guard-PI | jev | 60/80 | 0/80 |
| BIPIA | english-exact | 3/50 | N/A |
| Gandalf-Ignore | english-exact | 21/80 | N/A |
| InjecAgent | english-exact | 33/80 | N/A |
| LLMail-Inject | english-exact | 0/80 | N/A |
| LinguaSafe | english-exact | N/A | 0/30 |
| Lumees-Multilingual | english-exact | N/A | 0/30 |
| OR-Bench | english-exact | N/A | 0/200 |
| ObfuscationAugmenter | english-exact | 22/80 | N/A |
| PolyglotToxicityPrompts | english-exact | N/A | 1/30 |
| ToolEmu | english-exact | 0/20 | N/A |
| WildGuardMix | english-exact | N/A | 1/80 |
| deepset-prompt-injections | english-exact | 9/50 | 0/70 |
| jayavibhav-PI | english-exact | 9/80 | 4/80 |
| safe-guard-PI | english-exact | 12/80 | 0/80 |
| BIPIA | typed-exact | 0/50 | N/A |
| Gandalf-Ignore | typed-exact | 3/80 | N/A |
| InjecAgent | typed-exact | 3/80 | N/A |
| LLMail-Inject | typed-exact | 0/80 | N/A |
| LinguaSafe | typed-exact | N/A | 0/30 |
| Lumees-Multilingual | typed-exact | N/A | 0/30 |
| OR-Bench | typed-exact | N/A | 0/200 |
| ObfuscationAugmenter | typed-exact | 0/80 | N/A |
| PolyglotToxicityPrompts | typed-exact | N/A | 0/30 |
| ToolEmu | typed-exact | 0/20 | N/A |
| WildGuardMix | typed-exact | N/A | 0/80 |
| deepset-prompt-injections | typed-exact | 2/50 | 0/70 |
| jayavibhav-PI | typed-exact | 0/80 | 1/80 |
| safe-guard-PI | typed-exact | 0/80 | 0/80 |
| BIPIA | english-full | 6/50 | N/A |
| Gandalf-Ignore | english-full | 34/80 | N/A |
| InjecAgent | english-full | 38/80 | N/A |
| LLMail-Inject | english-full | 3/80 | N/A |
| LinguaSafe | english-full | N/A | 0/30 |
| Lumees-Multilingual | english-full | N/A | 1/30 |
| OR-Bench | english-full | N/A | 0/200 |
| ObfuscationAugmenter | english-full | 31/80 | N/A |
| PolyglotToxicityPrompts | english-full | N/A | 0/30 |
| ToolEmu | english-full | 0/20 | N/A |
| WildGuardMix | english-full | N/A | 1/80 |
| deepset-prompt-injections | english-full | 11/50 | 0/70 |
| jayavibhav-PI | english-full | 27/80 | 6/80 |
| safe-guard-PI | english-full | 25/80 | 2/80 |
| BIPIA | typed-full | 0/50 | N/A |
| Gandalf-Ignore | typed-full | 3/80 | N/A |
| InjecAgent | typed-full | 2/80 | N/A |
| LLMail-Inject | typed-full | 0/80 | N/A |
| LinguaSafe | typed-full | N/A | 0/30 |
| Lumees-Multilingual | typed-full | N/A | 0/30 |
| OR-Bench | typed-full | N/A | 0/200 |
| ObfuscationAugmenter | typed-full | 0/80 | N/A |
| PolyglotToxicityPrompts | typed-full | N/A | 0/30 |
| ToolEmu | typed-full | 0/20 | N/A |
| WildGuardMix | typed-full | N/A | 0/80 |
| deepset-prompt-injections | typed-full | 1/50 | 0/70 |
| jayavibhav-PI | typed-full | 3/80 | 1/80 |
| safe-guard-PI | typed-full | 3/80 | 0/80 |

## Diagnostic controls

60 contextual cases cover one complete four-context group per workflow family. Candidate-only/context-only controls remove fields intentionally; they are diagnostic, not evidence of authorized use without context. Reverse permutes compact option order.

| System/control | Final decisions changed vs full / 60 | Native choices changed / 60 |
|---|---:|---:|
| english-candidate_only | 11 | 25 |
| english-context_only | 5 | 21 |
| english-reverse | 2 | 7 |
| typed-candidate_only | 0 | 17 |
| typed-context_only | 0 | 7 |
| typed-reverse | 0 | 2 |

## Evidence and limitations

- All inputs are exposed development cases. Contextual labels are same-author and not independently reviewed; repeated delivery/context variants are correlated.
- The sample retained one fifth of each public source/truth quota by a frozen hash rank, independent of outcomes. Multilingual controls measure false alarms; there are no non-English positives.
- No token truncation is permitted. Both original-question and compact fit counts are saved in token-admission.json. Failures/abstentions remain in denominators; indeterminate truth counts as correct only when a valid model response produced it.
- Model, source, recipe, runtime and pack identities were frozen. All completed pass2 native runs were re-verified with the framework report command. Raw native probabilities and controls are retained.
- A first adapter attempt mistakenly required optional trusted_context on public cases. Its all-protocol-error results and the interrupted contextual run remain preserved. A protocol-only correction was frozen before the reported pass2; no sample, prompt or threshold changed.
- The first English contextual pass2 attempt timed out during startup before any corpus response; it is retained. A same-limit retry was used. Further zero-response startup failures, if any, are tracked in continuation-progress.json.
- No training, calibration fitting, shipping integration or default change occurred. Do not select new thresholds from these results and present them as independently calibrated.

Evidence: .cache/laya-experiment-20260919/. Reproduction scripts: crates/eval/scripts/decision_laya/.
