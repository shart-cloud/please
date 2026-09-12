# Excerpt display and analysis coverage

`Reason::excerpt_truncated()` records whether the displayed `matched` excerpt was shortened by a
detector or by finalization, including when sanitization expands characters beyond the display budget.
The flag stays with the reason when quoting or judge review suppresses it. The original span, finding
severity, model attribution, and input examined are unchanged. Human output marks shortened excerpts;
JSON emits `excerpt_truncated: true` on the affected reason.

Display shortening does **not** create an `incomplete` entry. If a judge demotes the last finding after
complete analysis, the verdict can become clean even when its retained, suppressed excerpt is short.
This repairs a presentation-induced review floor; it does not make detection more accurate.

`reasons_truncated` and `suppressions_truncated` describe shortened report lists. The retained
`Analysis` supplies all candidates to ML composition and review, even when `max_reasons=0` or
`max_excerpt_bytes=0`. Outcomes, scores, enabled tiers, and review request identities are independent
of these display limits.

Skipped input, failed decoding or inference, unavailable tiers, saturated matches, and exhausted
`max_observations` budgets remain analysis gaps. They survive demotion. The observation budget counts
both active and suppressed evidence. See [retained analysis](research/retained-analysis-2026-09-11.md).

## Wire compatibility

The new reason field is optional so the current schema still accepts historical verdicts. Current
producers omit it when false; absence in an older report does not establish that its excerpt was complete.
Consumers should accept the updated schema before ingesting new reports if they reject unknown fields.

`IncompleteCause::MaxReasons` / `max_reasons` and `ExcerptLength` / `excerpt_length` remain accepted for
compatibility. Current scanning no longer generates that gap for display truncation. Finalization does
**not** discard an explicitly supplied or historical gap: replay the original evidence under the new
semantics to compare results rather than silently rewriting an old verdict's incomplete status.

The original [dataset evaluation](research/dataset-evaluation-2026-09-11.md) and
[diagnosis](research/dataset-diagnosis-2026-09-11.md) retain their measured, pre-change results. See the
[presentation-only comparison](research/decision-semantics-2026-09-11.md) for the separate candidate.
The proposed [ML review contract](../specs/006-local-ml-tier/contracts/ml-review.md) is a distinct change
and is not enabled by this metadata correction.
