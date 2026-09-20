# Phase 2A contextual decision-model development result

Self-authored/self-reviewed development evidence. No independent holdout; no training or shipping changes from these local-model recipes. The separately requested Jev command is outside this comparison.

| Arm | Delivery | Macro recall | Determinate / answerable | Complete groups | False reassurance |
|---|---|---:|---:|---:|---:|
| G1 | repository_file | 0.0% | 0/120 | 0/40 | 0/40 |
| G1 | tool_response | 0.0% | 0/120 | 0/40 | 0/40 |
| G1 | user_input | 0.0% | 0/120 | 0/40 | 0/40 |
| N1 | repository_file | 30.0% | 43/120 | 0/40 | 6/40 |
| N1 | tool_response | 30.0% | 43/120 | 0/40 | 6/40 |
| N1 | user_input | 30.0% | 43/120 | 0/40 | 6/40 |
| N2 | repository_file | 15.8% | 23/120 | 0/40 | 2/40 |
| N2 | tool_response | 15.8% | 23/120 | 0/40 | 2/40 |
| N2 | user_input | 15.8% | 23/120 | 0/40 | 2/40 |

| Arm | Authorized recall | Conflict recall | Non-operative recall | Strongest one-sided control gain |
|---|---:|---:|---:|---:|
| G1 | 0/120 | 0/120 | 0/120 | -47.5% |
| N1 | 42/120 | 3/120 | 63/120 | -17.5% |
| N2 | 0/120 | 0/120 | 57/120 | -31.7% |

Development selection: N1. Eligible calibration points: 0/30.

STOP: no deployment or advisory authority; independent labels and holdout remain pending.

| Arm/device | Complete decisions | p50 ms | p95 ms | Peak RSS GiB | Peak GPU allocated GiB |
|---|---:|---:|---:|---:|---:|
| G1-cpu | 1440 | 137.6 | 278.9 | 0.94 | 0.00 |
| G1-cuda0 | 1440 | 51.5 | 172.7 | 1.35 | 0.57 |
| N1-cpu | 1440 | 440.4 | 3449.8 | 1.73 | 0.00 |
| N1-cuda0 | 1440 | 139.4 | 237.3 | 1.74 | 0.75 |
| N2-cpu | 1440 | 345.6 | 2628.8 | 1.48 | 0.00 |
| N2-cuda0 | 1440 | 127.3 | 471.9 | 1.48 | 0.60 |

The tables and JSON retain conflict recall, false reassurance and the gain over the strongest one-sided control. Abstention can avoid false reassurance while still failing coverage; it is not an effective classifier by itself.

There are 40 distinct primary development candidates across 10 workflow families and 20 calibration candidates across five families. Each is repeated under four contexts and three delivery types; delivery strata are correlated. Native bench contextual accuracy counts abstentions as misses; this report separately credits expected indeterminate outcomes only in group and missing-context metrics.

| Arm | Failed proposed gates |
|---|---|
| G1 | macro_recall, complete_groups, coverage, control_gain, cpu_timing_screen, gpu_timing_screen |
| N1 | macro_recall, complete_groups, coverage, control_gain, zero_false_reassurance, missing_context, cpu_timing_screen, gpu_timing_screen |
| N2 | macro_recall, complete_groups, coverage, control_gain, zero_false_reassurance, cpu_timing_screen, gpu_timing_screen |

The frozen shuffled pack has 120 disputed broad-task mappings, excluded from scored shuffled metrics after semantic self-review; the original run is preserved. This does not change primary development or calibration labels. Independent review is still needed.

Concurrent unrelated C++ compilation was observed in WSL; the later user-requested Jev build/tests also shared the host during CPU passes. Resource results are contention-affected, not an uncontended deployment benchmark.

Timings use successful measured decisions; coverage_states retain every attempted row, including timeout and unavailable results. Any separately identified same-limit retry is retained alongside its original failure.

Timing is screening evidence: three rotated model passes with a fixed shuffled case order and a single startup warmup. Length-bucket warmup remains outstanding.

See summary.json for label/source/workflow denominators, failures, all rejected calibration points, controls and family-cluster bootstrap intervals. Shared templates and delivery variants are correlated. Zero observed errors do not establish a sub-1% population error rate.

Independent label review and fresh blinded holdout collection remain external dependencies. No Colab account was accessed or corpus uploaded.

## Implementation and validation

The isolated evaluator now has frozen G1/N1/N2 adapters, exact model/tokenizer locks, 19 passing contract/data/report tests, official-path parity for all three models, and real 512/513-token boundary checks. All saved runs listed in the companion JSON passed the native verifier. The original failed ModernBERT GPU pass and preflight failures remain preserved.

The existing Python environment was reused without dependency changes. Phase 1 files, runs and public-corpus/shipping baselines remain intact; no new contextual accuracy is attributed to an artifact detector. The local-model experiment changed no shipping policy or cloud account. Separately, the user-requested opt-in Jev advisory command was implemented and tested; it does not use these local recipes or change ordinary scan decisions.

## Next decision

Stop these zero-shot recipes at the frozen gates. Review the authored labels and disputed shuffled mappings before deciding whether task-specific training is warranted. Collect independent, blinded workflow families for a later holdout; the current 720 main cases cannot become that holdout. Colab training and integration of these local recipes remain later conditional phases.

Reproduction: [decision_poc_v2 README](../../crates/eval/scripts/decision_poc_v2/README.md). Complete metrics, source/workflow denominators, calibration curves, reliability bins, model/code identities and native run hashes are in the companion JSON. Local evidence: .cache/decision-poc-v2-20260916/.
