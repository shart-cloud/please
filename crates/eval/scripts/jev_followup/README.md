# Jev contextual follow-up

This isolated, user-directed experiment tests four predeclared variants: A original request; B corrected structured context without a blanket permission-completeness assertion; C focused questions with B's same facts; D C plus caller-owned intent/permission availability and a deterministic missing-permission guard. No shipping CLI behavior changes.

Read the frozen plan in docs/research/jev-context-followup-plan-2026-09-16.md for hypotheses, selection, bounds and advancement gates. Screening uses 120 existing cases selected without prediction lookup and 36 new authored analysis-versus-redirection regressions. Only a same-information variant that passes all screening gates can advance to 360 remaining development cases and 240 calibration cases. These are exposed development data, not independent holdouts.

## Reproduce

From the repository root, using a fresh explicitly named cache for a new experiment:

```bash
python3 -m unittest discover -s crates/eval/scripts/jev_followup -v
python3 crates/eval/scripts/jev_followup/prepare.py
python3 -u .cache/jev-context-followup-20260916/code/run.py
python3 crates/eval/scripts/jev_followup/report.py
```

Preparation refuses an existing directory. The recorded source OUT constant identifies this run; a repeat requires a new name and a separately recorded budget, not overwriting this result. The captured CLI and the prior model/corpus caches are required. No dependency upgrade is necessary.

The credential prompt hides input. Credentials enter only the runner and HTTP worker environments, never filenames, command arguments, manifests or saved responses. The fixed TypeSafe endpoint refuses redirects. Each HTTP worker has a process-enforced 30-second deadline. Requests are sequential, with rotating arm order per case. The 1,250-attempt total includes one preserved authentication error caused by an incomplete token entered by Codex; the corrected session has a 1,249-attempt ceiling. No automatic retries or replacements occur.

## Evidence and guardrails

All existing candidate bytes and caller contexts are checked against the synthetic fixture generator. New cases are explicit synthetic fixtures. Labels, case IDs and expected outcomes never enter the API state. D's host fields come from the caller workflow and exact permission membership; label-scrambling checks establish that they are independent of ground-truth values. This does not make D a same-information model comparison: it receives additional caller facts and code guard behavior.

The native evaluator runs systems sequentially, so live requests are collected first in the desired interleaving. Native offline replay is then bound to capture hashes and exact candidate/context identities. Native replay reports zero new remote requests. Actual network counts, provider responses, raw response hashes, token usage and end-to-end times remain in live capture records. Replay speed is not API latency.

Invalid distributions and inconsistent choices remain failures with indeterminate outcomes. Raw responses are retained for diagnosis after credential-reflection checks; parser rules and confidence gates are not relaxed after outcomes. The report rechecks frozen inputs, recomputes decisions from captures and verifies native saved runs.

Twelve offline contracts cover composition, abstention, host-field provenance, label independence, response validation and replay binding. A preflight snapshot retains the version before an additional contradictory-component check; no model outcomes existed then. The separate auth-failure directory retains the one HTTP 401 and its blocked rows. Those rows are never merged into successful-screen quality metrics.

Independent review, fresh blinded workflow families, one-sided ablations and repeated provider consistency/latency trials remain outstanding. D's 30 predetermined missing-permission abstentions are explicitly separated from model-derived answers.
