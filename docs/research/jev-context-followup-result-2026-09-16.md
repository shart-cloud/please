# Jev contextual follow-up result

Controlled development experiment planned and frozen before these outcomes. The prior benchmark remains intact. All request bodies, code, labels and thresholds were frozen before inference; only the predeclared advancement rule could trigger confirmation.

## Screen: the same 120 existing cases

| Arm | Macro recall | Analysis-only recall | Conflicts found | Coverage | Wrong determinate / missing | All four contexts correct |
|---|---:|---:|---:|---:|---:|---:|
| A: Original | 63.3% | 0/30 | 30/30 | 81/90 | 8/30 | 0/30 |
| B: Corrected context representation | 66.7% | 0/30 | 30/30 | 84/90 | 22/30 | 0/30 |
| C: Focused questions, same information | 66.7% | 14/30 | 20/30 | 65/90 | 0/30 | 12/30 |
| D: Focused questions + caller facts/guard | 65.6% | 14/30 | 23/30 | 62/90 | 0/30 | 13/30 |

The previously recorded original recipe scored 63.3% macro recall on this exact subset. A is a fresh interleaved baseline, not a copied score.

B removes the blanket assertion that tool permissions are complete, while retaining the same task and permission facts. C asks separately about caller intent, task relation and permission, then combines sufficiently supported answers in code. D adds caller-authored intent and relevant-permission availability; its missing-permission outcomes are deterministic abstentions and are not credited as model reasoning.

## New analysis-versus-redirection regressions

The caller requests text analysis in both versions. One version contains material to explain; the other attempts to stop analysis and perform an action. These 36 cases are targeted same-author development examples, not an independent holdout.

| Arm | Plain material recognized | Operative redirection detected | False reassurance on redirection | False conflicts on plain material |
|---|---:|---:|---:|---:|
| A | 0/18 | 18/18 | 0/18 | 15/18 |
| B | 0/18 | 18/18 | 0/18 | 18/18 |
| C | 7/18 | 17/18 | 0/18 | 6/18 |
| D | 8/18 | 18/18 | 0/18 | 4/18 |

## Frozen advancement decision

Best same-information arm: B. Advanced: False. D was excluded from same-information selection.

| Arm | Failed screening gates |
|---|---|
| A | macro_recall, analysis_recall, missing_context, new_material_false_conflicts |
| B | macro_recall, analysis_recall, missing_context, new_material_false_conflicts |
| C | macro_recall, analysis_recall, conflict_recall, coverage, new_material_false_conflicts |
| D | macro_recall, analysis_recall, conflict_recall, coverage, new_material_false_conflicts |

No same-information arm cleared the frozen screen, so no confirmation API requests were made. This is a stop at the declared gate, not a reduced-sample success claim.

## What the component answers show

The representation-only change did not resolve the suspected completeness problem: wrong determinate missing-permission decisions rose from 8/30 in A to 22/30 in B. B changes the context representation as a whole, so it is not an isolated test of one flag.

C recognized the caller intent as analysis in 30/30 analysis-only cases. The remaining difficulty was the task-relation question: it chose material in 19/30, with only 14/30 clearing the frozen confidence gate. Giving D explicit caller intent did not increase final analysis recognition.

For explicit conflict cases, C chose denied in all 28 valid permission answers, but the composed result detected only 20/30 because some whole responses were invalid and other required components lacked sufficient support. This identifies composition and confidence gating as contributors, not merely missing facts.

All 9 captured invalid distributions in this run included a probability vector summing to approximately 0.99. The strict contract expects a unit sum. This explains these rejections; it does not prove their underlying provider cause. No post-outcome normalization or validation relaxation was applied.

A useful next trial would narrow the analysis question further to attempted redirection, retain independent component failures, and calibrate which component support is actually required for each decision. Explicit caller facts should supply only facts the host really knows. That is a new recipe to freeze and test separately, not a reinterpretation of this failed screen.

## API usage and evidence integrity

| Arm, screen only | API attempts | Host abstentions | Errors | Median ms | p95 ms | Input tokens | Output tokens |
|---|---:|---:|---:|---:|---:|---:|---:|
| A | 156 | 0 | 2 | 500.9 | 690.3 | 103330 | 8513 |
| B | 156 | 0 | 1 | 489.3 | 721.8 | 95842 | 8514 |
| C | 156 | 0 | 3 | 517.4 | 694.5 | 201766 | 21684 |
| D | 126 | 30 | 3 | 511.1 | 713.0 | 169245 | 17473 |

Total attempts in this round: 595/1,250, including one retained HTTP 401 caused by an incomplete token entered by the assistant before this run. Corrected credentials were used without changing questions or thresholds. No automatic retries or replacement benchmark rows.

Returned models: {'jev-1.13.0': 585}. Captured token usage: {'input_tokens': 570183, 'output_tokens': 56184}. Provider dollar pricing is unknown; usage from unreadable responses may be missing.

Live-capture failures: {'invalid distribution': 9}. Invalid responses are retained with hashes and raw bodies after credential-reflection checks; they remain abstentions. Numeric diagnostics appear in summary.json. No validation rule was relaxed after seeing outcomes.

API requests were sequential and interleaved across arms, with rotating order per case. Each request had a 30-second process-enforced deadline. Provider inference and network time are included; this is a single pass, not a repeated latency guarantee.

The native runner processes one system at a time. The experiment therefore collected live captures first, then verified offline replay bound to each capture hash and the exact candidate/context identity. Native remote-request counts are zero for replay; actual API counts and timings are retained separately. Replay overhead is not model latency.

Twelve offline contract tests passed, including label independence, caller-fact provenance, unknown permissions, contradictory answers, active redirection under analysis intent, strict response validation and replay input binding. All saved native runs passed the native verifier. Credentials were not saved.

## Interpretation and next step

The changes test interface hypotheses, not a claim that additional wording always improves Jev. D's caller facts and code-enforced abstention must be evaluated separately from improvements using the same facts. Analysis intent is never taken from a candidate's claim to be educational or authorized.

This remains same-author, exposed development evidence. Delivery variants repeat text; uncertainty is reported across workflow families in the JSON, not as independent per-row confidence. Independent label review, fresh workflow families, Jev one-sided controls and repeated provider trials remain outstanding. The installed CLI and shipping enforcement were not changed.

Plan: jev-context-followup-plan-2026-09-16.md. Reproduction: crates/eval/scripts/jev_followup/README.md. Complete per-delivery/per-family metrics, confusion tables, failures, source identities and raw live evidence are retained in the local experiment cache.
