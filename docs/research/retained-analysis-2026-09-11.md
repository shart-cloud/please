# Retained analysis and report projection — 2026-09-11

This is the next architecture-remediation slice after acquisition, preprocessing, and review binding.
The reproduced defect was `max_reasons=0` turning a `RiskFound/90` scan into `Inconclusive/0` and leaving
review with no candidates. Nonzero shortened lists also prevented ML composition and review.

## Representation and behavior

`Analysis` owns retained active and suppressed reasons, coverage gaps, calibration, input and policy
identity, and tier reports. `Verdict` holds this record plus a display projection. Optional tiers move
the retained record through `into_analysis()`; the former `Rebuild::from_verdict` report reconstruction
is removed. Scoring and outcome derivation read retained active evidence. Reports are attached to the
record; original reviewed evidence remains in the captured review scope after authorized demotions.

`Verdict::reasons()` and `suppressed()` remain display lists. Composition consumers use
`verdict.analysis().reasons()` and `suppressed()`. `Analysis::report(DisplayLimits { max_reasons,
max_excerpt_bytes })` can shorten or expand a projection without losing retained evidence. Excerpts
remain neutralized, and projection never sanitizes them a second time. `summary()` uses retained
findings so a zero-length display list still names the actual finding and score.

Structural matching and decoded/export excerpts use a fixed retained excerpt budget of 4096 bytes,
independent of display limits. That budget limits an excerpt, not the input examined by detection.
Producer-shortening flags remain visible. Review also receives the original bounded document.
Display settings are excluded from review scope identity, so changing them cannot change candidates,
prompt-visible IDs, or review execution. Ordinary scope version is v2 and prompt version is
`2026-09-11.6`; previous measured judge accuracy does not validate this changed model input.

## Analysis and request limits

`ScanPolicy::max_observations` and `Bounds::max_observations` default to 4096. The CLI exposes
`--max-observations`. Active findings and suppressions share this budget; demotion does not free slots.
Engine collection is bounded, finalization checks low-level caller evidence, and ML additions use the
remaining capacity without dropping structural evidence. Exhaustion adds one `max_observations` gap.
A zero analysis budget with observed findings is inconclusive. Releasing every retained finding after
exhaustion remains inconclusive because the gap survives.

The new cap bounds the retained observation lists. It is not a bound on every temporary detector
allocation, arbitrary caller-supplied metadata, or cumulative caller-added reports/gaps. Existing
input, matcher, ruleset, and decoding limits still apply. Low-level callers constructing `Evidence`
can opt into bounded collection with `Evidence::bounded`; `finalize` always enforces the retained cap.

Ordinary judge requests keep the 32 KiB document limit and have a separate 128 KiB evidence budget,
measured as escaped excerpts plus 128 bytes per candidate for IDs and envelope overhead. Exceeding it
refuses the request with a tier gap before network I/O. This is not a display setting.

Historical `max_reasons` and `excerpt_length` gaps supplied by callers remain preserved. Current
report shortening sets display flags and never generates those gaps. Rust callers constructing
`Bounds` or `ScanPolicy` with complete literals must add `max_observations`; JSON consumers must accept
the updated schema, including the policy field and new gap cause.

## Verification and remaining scope

Regression tests cover zero and nonzero report limits, unchanged review wire requests, structural →
ML → advisory/authorized review → later failure, retained suppressions, genuine budget exhaustion,
request budgets, re-projection, CLI exit codes, and schema validation. No live remote judge request,
model-weight inference, corpus sweep, or accuracy claim is part of this slice.

The broader review still has open work: explicit enforcement profiles and trusted caller context;
raw model score versus assessed impact; shared CLI/evaluation composition; complete inference
identity; chunk scores, overlap, and boundary-placement evaluation. Evaluation localization now reads
retained findings, but the shared shipping pipeline remains a separate task.

Validation completed for this slice:

- Full core and ML suites with Candle: `/tmp/bee-analysis-core-ml.log`; default ML unit tests:
  `/tmp/bee-analysis-ml-default.log`.
- Full judge suite: `/tmp/bee-analysis-judge.log`; final request/binding/ML-review tests:
  `/tmp/bee-analysis-judge-final.log`; expanded zero-display contextual HTTP regression:
  `/tmp/bee-analysis-contextual-zero.log`.
- CLI suite with `ml-candle`: `/tmp/bee-analysis-cli.log`. Its sole failure was a substring assertion
  matching the number 77 inside a new opaque evidence ID; the test now checks JSON numeric values.
  All 12 corrected judge CLI tests pass in `/tmp/bee-analysis-cli-judge-final.log`. All 16 schema
  contract tests passed in `/tmp/bee-analysis-cli-contract.log`.
- Standalone eval library: 58 passing tests in `/tmp/bee-analysis-eval.log`.
- Clippy across core, judge, CLI, and ML, all targets with `please-cli/ml-candle`, using `-D warnings`:
  `/tmp/bee-analysis-clippy.log`. Offline CLI check: `/tmp/bee-analysis-offline.log`.
- Workspace and eval formatting, diff whitespace, core isolation, core dependency allow-list, offline
  CLI dependency guard, and default ML isolation checks pass.

Mock HTTP tests ran outside the filesystem sandbox because local socket binding is blocked inside it.
Ignored live-service and real-weight tests were not run. Changes remain uncommitted in the existing
working tree.
