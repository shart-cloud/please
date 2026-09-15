# Follow-up: role-marker prefilter and newly visible saturation

**Status (2026-09-15): accepted and enabled in the built-in rules.** The user
explicitly accepted the documented saturation exception ("i accept them"). The
[preserved patch](role-marker-prefilter-candidate.patch) contains the applied
literal correction, shipping-engine regression tests, and their required fixture.
This is separate from the [email-rule withdrawal](detection-review-response-2026-09-14.md).

## Finding

`boundary.forged_role_marker` accepts bracketed, angle-delimited, and spaced role
markers. Its literal prefilter admits only a subset of those spellings. The saved
E1 experiment changed its literals from `system:`, `assistant:`, `[system]`,
`<|im_start|>`, and `### system` to `system` and `assistant`. Its regex, frame
eligibility, severity, suppression, and resource bounds stayed unchanged.

On the frozen LLMail set, detections rose from **11,263 to 12,239 (+976)**,
with no lost detections. The prior experiment found no added benign false positives
on its frozen controls. Existing coverage causes remain reported. Distinct
incomplete rows rose **154 → 157**. These are development results, not new-family
validation or sufficient evidence to deploy the change.

## Three newly visible gaps

The review response replays the saved baseline and E1 binaries against exactly
these three rows and reproduces the original native results. A separate bounded
Rust diagnostic uses the actual rule regex and `FrameMap` on their raw bytes.

| Row ID | Bytes | Raw regex matches | Frame-eligible matches, all / first 16 | Baseline → E1 |
|---|---:|---:|---:|---|
| `3096a57c528bea49` | 3,647 | 18 | 0 / 0 | High → High plus incomplete |
| `d2ac22d03a13dd9b` | 3,180 | 24 | 0 / 0 | Clean → inconclusive |
| `de487116dcd21af2` | 2,990 | 24 | 0 / 0 | Clean → inconclusive |

For all three raw inputs, the old prefilter rejects the role rule; the corrected
prefilter admits it. The existing matcher collects up to 16 raw occurrences and
checks one extra to report saturation **before** testing frame eligibility.
The extra eligible-role-match count is zero here, including after the first 16.
The first row retains its separate `agent_directed.addressed_marker` finding.

Thus E1 exposes an existing bounded-analysis limitation. It does not remove an
existing detection or shrink the scan budget. “Clean” becoming “inconclusive” on
two rows is more explicit coverage reporting. The gap should not be suppressed
merely because this separate offline diagnostic could inspect all 18 or 24 raw
matches. Production scanning still stopped at its established bound.

The diagnostic is capped at 129 raw matches and asserts that cap is not reached.
It runs outside the production path on the three short frozen rows. Its exhaustive
counts describe these raw inputs only; they are not a claim about every decoded
representation or the entire benchmark.

## Acceptance decision

The original goal forbade any increase in distinct incomplete rows, so rejection
of E1 was correct under that criterion. **That rejection does not establish reduced
analysis capability.** The possible benefit of more honest reporting is a reason
to revisit the criterion explicitly, not to silently reinterpret a passing result.

The user accepted newly observable pre-existing saturation separately from new
resource exhaustion or lost analysis on September 15, after reviewing the
validation below. The exception is limited to this measured patch and the
documented rows and gap records; it does not authorize relaxing scan limits.

The required follow-up work, now completed and documented below, was:

1. Retain the saved baseline/E1 delta and all three gaps as regression evidence.
2. Validate role-marker syntax and ordinary role mentions with fresh controls,
   disclose label authorship, and measure candidate-prefilter runtime costs.
3. Audit frame eligibility and raw-match saturation together. Any alternative
   matcher must preserve bounded work and explicit incompleteness. Repeated regex
   searching can be quadratic; an unbounded search for eligible matches is not an
   acceptable substitute for the fixed raw-match cap.
4. Report added findings, lost findings, old and new gap causes, and latency
   separately under the explicitly chosen acceptance criterion.

No limits were raised or gaps suppressed. The only shipping change is the
role-marker rule's literal list.

## Evidence and reproduction

- Historical candidate: `.cache/detection-improvement-20260914/e1/` contains
  `rules.patch`, `builtin.toml`, `role_marker_prefilter.rs`, and `frozen-corpus`.
- Full delta: `baseline-high-01--e1-full-01.json` under the same experiment root.
- Review response root: `.cache/detection-review-response-20260914/` contains
  `role-marker-inputs.json`, native `role-marker-baseline` and `role-marker-e1`
  runs, `role-marker-diagnostic-v2.jsonl`, and `summary.json`.
- [Diagnostic source](../../crates/core/examples/role_marker_review.rs): run
  `cargo run --locked --offline -p please-core --example role_marker_review -- .cache/detection-review-response-20260914/role-marker-inputs.json`.

The initial diagnostic's TOML parse failure and empty output are preserved with
their log. The corrected `v2` diagnostic uses the document parser and completes.
Upstream attack text stays in the existing local cache; this follow-up publishes
only row IDs, counts, and findings.

## September 15 implementation and validation

The [machine record](role-marker-prefilter-2026-09-15.json) contains counts,
native gap diagnostics, timings, and evidence hashes. New local artifacts are in
`.cache/role-marker-follow-up-20260915/`. Historical E1 and review evidence was
verified unchanged. The candidate changes only this rule's literal list to
`system` and `assistant`; its regex, anchor, severity, suppression, and every scan
limit remain unchanged. No matcher implementation changes are needed.

### Accepted criterion — September 15

The explicitly accepted exception allows **exactly the three newly incomplete
frozen LLMail rows listed above**,
plus the additional role-rule saturation records on three already incomplete
rows listed below. Every added gap must identify the role rule at the existing
16-match limit; all existing gap records and native findings must remain present.
It permits no other newly incomplete rows, no new resource-limit category, no
lost detections, and no added benign findings in the evaluated controls.

This is an acceptance decision for this measured patch, not a general exemption
for future increases in incompleteness. Runtime costs below are part of the
review. The measured patch satisfies this accepted criterion. Under the original
zero-increase criterion, it **still fails**; that historical result is preserved.
The acceptance criterion changed explicitly; no automated regression baseline,
threshold, gate, or scan limit was changed.

### Reproduction and fresh controls

The regression tests failed twice on the baseline: valid spaced markers were
missed, and off-frame repetition silently skipped the role-rule match cap. The
literal-only candidate fixes both. Tests also prove that a valid marker after
the first 16 raw matches remains unexamined and reports a gap.

The [109 fresh controls](../../crates/core/tests/data/role_marker_controls.jsonl)
contain 84 role-syntax cases and 25 ordinary-prose cases. They cover bracketed,
angle-delimited, and colon forms; mixed ASCII case; tabs and nonbreaking spaces;
sentence and comment boundaries; headings without colons; non-role words; and
role notation away from a frame boundary. All are exercised directly and through
base64 using the shipping engine. The tests check original encoded spans and
decoding chains as well as findings and coverage. Further transforms can produce
multiple decoded representations; one encoded input need not mean one finding.

Codex authored and checked these controls on September 15; there is **no
independent label review**. Positive labels assert a role-marker mechanism at a
frame boundary, not task-level authorization or successful exploitation. These
are development checks, not unseen-family validation. The changed literals
address the documented delimiter/spacing mismatch; they do not establish a
general Unicode case-folding guarantee for the ASCII literal prefilter.

Native product/enforcement/High results on the new direct-input controls are
**6 → 84 / 84 syntax detections**, **0 → 0 / 25 benign detections**, and zero
incomplete rows in either version. Regression tests additionally exercise the
decoded forms, 16/17/18/24 raw-match counts, and lazy compilation: ordinary role
words now compile the regex without becoming findings.

### Frozen-corpus results

Both versions use the same current evaluator build configuration and immutable
input packages, with separately saved release binaries. All 14 development
slices ran three times in alternating baseline/candidate order; native per-row
results are identical across repeats. The full LLMail native rows reproduce
historical baseline and E1 results exactly, including all three gap transitions.

| Slice | Rows | Baseline High | Candidate High | Newly incomplete |
|---|---:|---:|---:|---:|
| LLMail | 27,963 | 11,263 | 12,239 | 3 |
| InjecAgent | 1,054 | 442 | 442 | 0 |
| Obfuscation development | 9,855 | 444 | 454 | 0 |
| Stratified development | 7,281 | 1,786 | 1,800 | 0 |
| OR-Bench benign | 3,000 | 0 | 0 | 0 |
| Previously exposed validation attacks | 300 | 87 | 87 | 0 |
| Previously exposed validation benign | 300 | 0 | 0 | 0 |

There are **no lost native findings or detections** in any replayed slice. Added
native finding records are 3,871 on LLMail, 10 on obfuscation, and 49 on the
stratified slice. Findings and newly detected rows are different denominators:
a row can already be detected or gain several findings.

All 14 added stratified detections exactly duplicate LLMail input text. The ten
added obfuscation detections contain ten distinct strings and no exact LLMail
duplicates, but they are already-exposed development inputs; this does not
establish independent attack-family transfer. The previous 600-row validation
set is now exposed and supplies regression evidence only.

All negative native findings, detection counts, and coverage remain unchanged:
clean negatives 516/6,640; non-adversarial negatives 534/13,169; multilingual
negatives 19/3,196; benign fixtures 14/20; matched negatives 0/14; frozen repository
prose 32/87; and OR-Bench 0/3,000. These are raw counts retaining the frozen
exclusions and denominators, not evidence that the overall benign gate passes.
The unchanged remaining positive counts are BIPIA 16/394, fixtures 42/51, and
generated positives 316/1,060. InjecAgent still does not meet the earlier
495-detection target; the withdrawn email rules remain withdrawn.

### Coverage audit: distinct rows and gap records

LLMail has **154 → 157 distinct incomplete rows**. Seven added native gap records
occur across six rows. All seven identify `boundary.forged_role_marker`, cause
`max_matches_per_rule`, configured limit 16. All old gap details and scores on
these six rows are preserved; the other three rows were already incomplete due
to `solicitation.actionable_disclosure`.

| Row | Baseline status | Added role-gap records | Raw role matches inspected |
|---|---|---:|---:|
| `3096a57c528bea49` | Complete, High | 1 | 18, exhaustive |
| `d2ac22d03a13dd9b` | Complete, Clean | 1 | 24, exhaustive |
| `de487116dcd21af2` | Complete, Clean | 1 | 24, exhaustive |
| `2b309df81a89be3a` | Already incomplete | 1 | 40, exhaustive |
| `a586afd7c0f9b6cd` | Already incomplete | 2 | 30, exhaustive |
| `f230bbaefbda26ad` | Already incomplete | 1 | At least 129; diagnostic capped |

No inspected raw occurrence is frame-eligible. The six-row diagnostic initially
hit its 129-match assertion; that failure is retained. Its extended mode now
reports a partial count explicitly for the longer row and compares native gap
details without raising either the diagnostic cap or production bounds. Raw
counts do not exhaustively describe decoded representations. Multiple gap
records on one row must not be collapsed into an assertion of one scan path.

The source audit confirms both direct and decoded matching collect at most 16
raw spans and probe one more before frame filtering. Each buffer owns its frame
metadata. The fix changes only candidate admission, so it exposes work previously
skipped. An eligibility-first retry loop would change the work bound and is not
part of this patch. Existing frame-matching tests continue to cover zero caps,
quoted suppression, display limits, and both coordinate spaces.

### Runtime costs and checks

Full 14-slice evaluation medians are **18.919 s baseline → 19.247 s candidate
(+1.73%)**, including evaluator I/O and reports. Individual total times are
19.097/18.919/17.714 s baseline and 19.247/19.339/18.435 s candidate (execution
order is preserved in `timings.json`). LLMail slice medians are 11.978 → 12.207 s.
Three repetitions on one machine do not establish a precise performance ratio.

The [matcher cost probe](../../crates/core/examples/role_marker_cost.rs) uses
the actual lazy matcher with identical 16-match bounds, alternating order,
15 cold and 135 warm samples per input size. Parsing and construction are
excluded; cold scans include first-use regex compilation.

| Input | Size | Baseline warm median | Candidate warm median |
|---|---:|---:|---:|
| Ordinary prose | 4 KiB | 9.99 µs | 10.12 µs |
| Repeated ordinary role mentions | 4 KiB | 9.61 µs | 22.56 µs |
| Repeated ordinary role mentions | 1 MiB | 2.50 ms | 5.76 ms |
| Repeated off-frame markers | 1 MiB | 2.48 ms | 2.55 ms |

The 4 KiB role-mention cold median rises from 10.45 µs to 454.44 µs because the
regex now compiles. Ordinary role-heavy prose pays a measurable cost even when
it produces no findings. Saturating marker repetition remains bounded.

Candidate validation passed: full workspace tests, full standalone evaluator
tests, both all-target Clippy checks with warnings denied, formatting, dependency
and isolation guards, and `git diff --check`. Release scaling tests passed:
growth exponent 0.929, 4 KiB p95 546.5 µs, sustained throughput 8.9 MB/s. The
existing throughput regression floor passes; the separate 10 MB/s product target
was **not met** in this run. No threshold was changed.

After acceptance and application, all eight targeted role-marker/frame tests,
core all-target Clippy, both formatting checks, and `git diff --check` passed
again. The evidence audit reproduced every measured result and evidence hash;
only the recorded acceptance status and decision metadata changed.

### Verifying the applied change or reproducing the candidate

The accepted patch is applied. It includes the literal change, four tests
that exercise `Engine::builtin()`, and `data/role_marker_controls.jsonl`.
The built-in rule file is byte-identical to the tested candidate snapshot, and
`git apply --reverse --check` verifies that the preserved patch matches the
applied rule, tests, and fixture. Run the targeted regressions with:

```bash
cargo test --locked --offline -p please-core \
  --test role_marker_prefilter --test frame_matching
```

To reproduce on a checkout of the original baseline, apply the preserved patch
with `git apply docs/research/role-marker-prefilter-candidate.patch` first. Do not
reapply it to the current tree. Existing measurements can be audited using the
explicit saved baseline and candidate rules:

```bash
cargo run --locked --offline -p please-core --example role_marker_review -- \
  .cache/role-marker-follow-up-20260915/all-gap-inputs.json \
  .cache/role-marker-follow-up-20260915/baseline.toml \
  .cache/role-marker-follow-up-20260915/candidate.toml

cargo run --release --locked --offline -p please-core --example role_marker_cost -- \
  .cache/role-marker-follow-up-20260915/baseline.toml \
  .cache/role-marker-follow-up-20260915/candidate.toml

cargo build --release --locked --offline --manifest-path crates/eval/Cargo.toml \
  --bin please-eval
python3 crates/eval/scripts/detection_experiment/audit_role_marker_follow_up.py \
  .cache/role-marker-follow-up-20260915 /tmp/role-marker-audit-new.json
```

The [native replay runner](../../crates/eval/scripts/detection_experiment/role_marker_follow_up.py)
takes a new output root and baseline/candidate frozen-runner binaries. Copy
`preserved.json` and `baseline.toml` into that root first. It records package and
binary identities, saves every native row, checks historical LLMail equality,
and refuses to overwrite evidence. The output paths must be new; rerunning
already exposed corpora is a regression check, not fresh validation.

### Evidence-tooling review corrections — September 15

The focused review independently confirmed the native detection counts but found
that the initial auditor trusted summary totals, the patch omitted its fixture,
and the older email report's build command no longer selected its historical
detector. Those tooling defects are corrected; the detector is unchanged.

The auditor now uses `please-eval`'s native saved-run verifier and recomputes
counts and differences from checksum-verified row bytes. It requires exact
agreement with `summary.json`, verifies input identities, selection, pipeline
consistency, repeats, and historical LLMail rows, and rechecks preserved artifacts.
The corrected [machine record](role-marker-prefilter-2026-09-15.json) includes the
verifier and native-file hashes. All previously reported measurement values are
unchanged. Integrity checks establish consistency, not an independent label
review or protection against coordinated replacement of the entire evidence set.

The exact corrupted-summary review case now fails before publishing a report.
Synthetic native-run regressions also cover incorrect counts/differences,
changed native rows, incomplete runs, missing completion, input identities, and
pipeline metadata. The fixture-inclusive patch passes all eight focused tests
when applied to a clean export of baseline commit `90f5676`.

See the [current reproduction guide](detection-reproduction-current.md) for the
commands, including the explicitly frozen withdrawn email candidate that
reproduces 510 InjecAgent detections. The historical email report and its machine
record remain byte-for-byte unchanged.
