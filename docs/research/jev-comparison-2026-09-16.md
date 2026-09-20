# Jev versus the existing Please benchmarks

One live pass through all 1,950 existing cases. All five saved runs passed native verification. No prompt, label or deployed threshold was changed after viewing dataset outcomes.

## Contextual development: same 480 cases

| Model | Macro recall | Answerable coverage | All four contexts correct | False reassurance on conflicts | Wrong determinate with missing context |
|---|---:|---:|---:|---:|---:|
| Jev | 65.6% | 322/360 | 0/120 | 0/120 | 45/120 |
| G1 | 0.0% | 0/360 | 0/120 | 0/120 | 0/120 |
| N1 | 30.0% | 129/360 | 0/120 | 18/120 | 6/120 |
| N2 | 15.8% | 69/360 | 0/120 | 6/120 | 0/120 |

Abstentions count as misses on answerable cases. Full-group correctness credits the expected indeterminate outcome. These are 40 candidate texts across ten workflow families, repeated under four contexts and three delivery types; the 480 rows are correlated.

| Delivery | Macro recall | Aligned recall | Conflict recall | Non-operative recall |
|---|---:|---:|---:|---:|
| repository_file | 65.8% | 39/40 | 40/40 | 0/40 |
| tool_response | 65.0% | 38/40 | 40/40 | 0/40 |
| user_input | 65.8% | 39/40 | 40/40 | 0/40 |

Family-cluster descriptive macro-recall interval: 63.3% to 66.7%. This is not an independent population confidence claim.

Native Jev choices before the frozen abstention gate have 68.1% macro recall; this is diagnostic only, not a replacement operating point.

Calibration: 0/30 predeclared threshold/margin combinations met the existing coverage, benign false-conflict and missing-context gates with confidence fixed at 0.5. The installed 0.7 support / 0.15 margin / 0.5 confidence gate remains unchanged.

Passed quality gates: false_reassurance.
Failed quality gates: macro_recall, complete_groups, coverage, missing_context, eligible_calibration.

## Earlier public/artifact comparison

This separate benchmark-only Choice prompt detects injection versus benign content. It is not the contextual plz clap command. Public labels are inherited, previously exposed, and not owner-adjudicated.


| System | All attacks detected | All benign false positives | Incomplete |
|---|---:|---:|---:|
| Jev | 246/330 | 1/300 | 57 |
| structural | 105/330 | 2/300 | 0 |
| structural_ml | 295/330 | 74/300 | 0 |
| gliclass-binary-cuda0 | 249/330 | 119/300 | 1 |
| gliclass-decomposed-cuda0 | 330/330 | 299/300 | 1 |

Hypothetical structural OR Jev, computed only from saved outputs: 252/330 attacks and 3/300 benign false positives; 147 added detections and 1 added false positive relative to structural alone. No shipping policy was changed.

| Source | System | Attacks detected | Benign false positives | Incomplete |
|---|---|---:|---:|---:|
| Gandalf-Ignore | Jev | 86/100 | 0/0 | 9 |
| Gandalf-Ignore | structural | 60/100 | 0/0 | 0 |
| Gandalf-Ignore | structural_ml | 100/100 | 0/0 | 0 |
| Gandalf-Ignore | gliclass-binary-cuda0 | 78/100 | 0/0 | 0 |
| Gandalf-Ignore | gliclass-decomposed-cuda0 | 100/100 | 0/0 | 0 |
| OR-Bench | Jev | 0/0 | 0/100 | 0 |
| OR-Bench | structural | 0/0 | 0/100 | 0 |
| OR-Bench | structural_ml | 0/0 | 4/100 | 0 |
| OR-Bench | gliclass-binary-cuda0 | 0/0 | 27/100 | 0 |
| OR-Bench | gliclass-decomposed-cuda0 | 0/0 | 100/100 | 0 |
| first_party_contextual_pilot | Jev | 20/30 | 0/0 | 7 |
| first_party_contextual_pilot | structural | 4/30 | 0/0 | 0 |
| first_party_contextual_pilot | structural_ml | 23/30 | 0/0 | 0 |
| first_party_contextual_pilot | gliclass-binary-cuda0 | 14/30 | 0/0 | 0 |
| first_party_contextual_pilot | gliclass-decomposed-cuda0 | 30/30 | 0/0 | 0 |
| jayavibhav-PI | Jev | 68/100 | 1/100 | 26 |
| jayavibhav-PI | structural | 9/100 | 2/100 | 0 |
| jayavibhav-PI | structural_ml | 97/100 | 70/100 | 0 |
| jayavibhav-PI | gliclass-binary-cuda0 | 87/100 | 62/100 | 0 |
| jayavibhav-PI | gliclass-decomposed-cuda0 | 100/100 | 100/100 | 0 |
| safe-guard-PI | Jev | 72/100 | 0/100 | 15 |
| safe-guard-PI | structural | 32/100 | 0/100 | 0 |
| safe-guard-PI | structural_ml | 75/100 | 0/100 | 0 |
| safe-guard-PI | gliclass-binary-cuda0 | 70/100 | 30/100 | 1 |
| safe-guard-PI | gliclass-decomposed-cuda0 | 100/100 | 99/100 | 1 |

## Supplemental packs

Earlier contextual pilot: 33.3% macro recall across 90 cases. It uses conspicuous task templates and is weaker evidence than the four-context pack.

Shuffled-context results exclude the same 120 previously disputed mappings; all original rows and outcomes remain saved. The 18 semantic challenge cases are reported separately from six malformed/byte-boundary cases and six local-model-specific marker/token-boundary cases.

## Timing, usage and failures

| Pack | Successful remote calls | End-to-end p50 ms | End-to-end p95 ms |
|---|---:|---:|---:|
| development | 475 | 327.1 | 422.1 |
| calibration | 240 | 328.1 | 394.1 |
| shuffled | 475 | 338.0 | 420.4 |
| challenge | 24 | 346.3 | 421.7 |
| pilot | 719 | 354.6 | 432.4 |

Model responses: {'jev-1.13.0': 1933, 'no response': 17}. The request used jev-latest; returned model identifiers are retained per row, but provider weights are not locally pinned.

Dataset API attempts: 1944. Successful-response token usage: 1,213,329 input / 99,100 output. Two separate demonstration smoke requests are outside dataset metrics. Pricing was not available, so dollar cost is unknown.

Rows with errors or refusals: 17 (11 remote/response failures; 6 local input refusals, including the intentionally malformed/oversized fixtures). All failures remain in the quality denominators; no benchmark row was retried or replaced; separate follow-up diagnostics are described below. The first local setup failure occurred before dataset evaluation and remains in decision-jev-20260916-preflight-1.

Jev latency includes network, provider execution, context mapping and CLI startup. The local models used warm local inference on a shared host affected by other work. These figures do not establish an apples-to-apples hardware speedup or an uncontended deployment budget.

## Interpretation

This is a comparison of the frozen recipes and adapters on exposed development data, not intrinsic model capability or an unseen deployment benchmark. Jev has an explicit fourth indeterminate option and a confidence gate; local recipes use three independently scored hypotheses. Contextual task text is preserved, while permission entries are mapped into the shipping caller-context schema with unlisted permissions explicitly unspecified. No expected labels or case/source metadata are sent. Jev-specific candidate-only/context-only ablations and repeated API trials were not run; this bounded comparison cannot establish their control-gain or repeatability gates.

Independent label review and a fresh blinded holdout remain required before changing enforcement or release authority. Jev remains advisory. If any quality gate fails, stop at this operating point instead of relaxing requirements.

## Reproduction and integrity

The isolated scripts, frozen recipe, pinned CLI, pack copies and code hashes are under .cache/decision-jev-20260916. Native saved-run verifiers check each completed run. The credential broker uses a private local socket and memory-only credential; no credential is stored in benchmark manifests, files or reports. The actual outgoing data was checked against synthetic generators and the pinned public dataset freeze; repository_file and tool_response are simulated delivery labels.

Official request/response contract: https://docs.typesafe.ai/api. Full per-source/per-workflow denominators, calibration grid, paired family bootstrap differences, confusion tables, probabilities, token usage and failures are retained in summary.json and native results.

## Response-validation diagnostics

After the frozen benchmark, 5 selected rejected development cases were queried again for diagnosis. All five fresh responses passed distribution/choice validation; the original invalid response bodies were not retained, so their cause remains unresolved. These are post-outcome follow-up requests, not repeated-trial accuracy evidence. No original result was replaced.

Total API attempts including two demonstration smokes and five diagnostics: 1951/2,000. Invalid original responses can have unreported token usage; saved token totals are not a billing total.
