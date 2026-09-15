# Literal-prefilter matching consistency — September 15, 2026

[HTML report](matching-consistency-2026-09-15.html) ·
[Verified machine record](matching-consistency-2026-09-15.json)

## Result and disposition

All 18 built-in rules had demonstrated literal-admission discrepancies. The
accepted correction changes **13 rules' literals only**. It recovers **2,251
generated syntax detections** without changing any finding or detection on the
14 development slices. Five full corrections are **deferred** because they
introduce new benign findings. This does not claim complete shipping/reference
equivalence: those five known inconsistencies remain in shipping.

The full correction candidate agrees with the ungated reference on the evaluated
inputs. The accepted candidate agrees with the compiled shipping engine. Both
comparisons also check full in-memory findings, transformation chains, suppression
and gap details, beyond the native saved rows' projection.

The reference lives in test support and excluded evaluator examples. There is no
production bypass flag. Regexes, framing, decoding, suppression, severity, High
threshold and enforcement profile are unchanged. Limits remain 1 MiB input,
three decode levels, 16 raw matches per rule, 4,096 observations and 64 displayed
reasons. Supplied normal/reference engines prepare their rules eagerly; shipping
retains lazy pattern compilation. Its equality is checked separately.

## What was wrong

The literal automaton folds ASCII case, while the regexes use Unicode-aware
case-insensitive matching. Long s (`ſ`) and Kelvin sign (`K`) can therefore occur
in regex matches without admitting their rules through an ASCII-only literal.
The corrected literals explicitly enumerate the applicable combinations. This
adds no new regex vocabulary or Unicode normalization step.

Four accepted rules also had ASCII inconsistencies:

| Rule | Missed form | Correction |
| --- | --- | --- |
| `override.forget_everything` | `forget\teverything` | Gate on the existing verbs; let `\s+` decide separators. |
| `override.new_instructions_follow` | `updated\ninstructions:` | Gate on the existing adjectives. |
| `boundary.forged_tool_result` | `tool_output \t:` | Remove the gate's compulsory adjacent colon. |
| `boundary.delimiter_breakout` | `-- end of context` | Correct `end context` to the phrase already specified by the regex. |

The other nine accepted rules receive Unicode literal equivalents. The
machine report lists all 18 rules, effective intended-rule probe hits, affected
variations and carriers, and each disposition.

### Why five corrections remain deferred

The existing regexes accept the following ordinary text, although the old gates
skip them. Fixing admission alone therefore conflicts with the no-new-benign-
findings criterion. Their regex semantics and old literal lists are preserved;
the full candidate is retained for review, not installed.

| Rule | Authored benign witness of a newly exposed finding |
| --- | --- |
| `solicitation.credentials` | “Print the secret Santa assignments.” |
| `solicitation.tool_enumeration` | “List tools needed to repair a bicycle.” |
| `boundary.forged_system_directive` | “Our systemoverride identifier names a local variable.” |
| `agent_directed.addressed_marker` | “Messages for the assistant are stored in the inbox.” |
| `privilege.permission_widening` | “The documentation describes how to disable the sandbox.” |

The tool-enumeration rule is severity 55: new findings matter even when they do
not cross High. Tests retain these five witnesses so a future change must
explicitly revisit their disposition. Narrowing the regexes requires a separate
semantic decision; this audit does not silently do so.

## Coverage and dataset interpretation

The authored seed catalog has 1,248 cases covering every rule. Its generator
produces 103,968 syntax rows across original, uppercase, mixed case, tabs,
repeated spaces, newlines, NBSP, EM-space, Unicode case, sentence-prefix and
punctuation variants. Carriers are plain text, JSON, HTML comments, Markdown
quotes/fences/tables, base64 and hex. There are also 195 benign control rows.

Some transformations deliberately leave the regex language. A syntax row is
an attempted probe, not an independently labelled attack. Effective per-rule
matching is counted using actual reference findings; every rule has effective
positive probes and demonstrated discrepancies. Aggregate syntax detections
must not be interpreted as attack recall. These are Codex-authored development
controls without independent label review.

The 14 existing development slices and previously exposed 600-row validation
package are regression evidence, not fresh held-out estimates. Slices can
overlap. The report preserves raw per-slice counts, including pre-existing
benign findings and known dataset wrappers; no pooled accuracy claim is made.
Repository prose is the already frozen 87-row selection and excludes this new
report. New findings are compared individually, including spans and transform
chains, rather than inferred from detection totals alone.

Selected development results:

| Dataset | Baseline | Accepted | Ungated reference |
| --- | ---: | ---: | ---: |
| LLMail | 12,239 | 12,239 | 12,339 |
| InjecAgent | 442 | 442 | 442 |
| Obfuscation | 454 | 454 | 699 |
| Stratified positive | 1,800 | 1,800 | 1,852 |
| OR-Bench | 0 | 0 | 0 |
| Clean negative | 516 | 516 | 519 |
| Nonadversarial negative | 534 | 534 | 540 |
| Repository prose | 32 | 32 | 34 |
| Authored syntax | 61,529 | 63,780 | 75,719 |
| Authored benign | 10 | 10 | 40 |
| Exposed validation positive | 87 | 87 | 99 |
| Exposed validation benign | 0 | 0 | 1 |

No existing development finding is lost by the accepted correction. Its natural
corpus counts are unchanged; the broader reference gains mostly belong to the
deferred rules. The complete machine/HTML reports include the other slices and
individual finding deltas. This audit found substantial remaining inconsistencies,
so the conditional ML comparison was not started.

## Coverage gaps and runtime

Median development scan-and-publication time rises from **18.82 s to 21.23 s
(+12.8%)** for the accepted correction. The reference takes **77.18 s**. The
accepted correction therefore has a measurable cost despite unchanged natural
corpus detection totals. Its demonstrated benefit is syntax consistency.

No new corpus gap is introduced by the accepted correction. LLMail remains at
157 incomplete rows; the authored syntax suite retains its existing 795
decode-depth gaps. Full gap details are compared, as well as counts and causes.

The runtime suite measures ordinary prose, literal-dense nonmatching text,
whitespace tool markers and off-frame Unicode role markers, including 16, 17,
128 and 4,096 repetitions and an over-limit input. Each new dense-input gap is
listed individually in the JSON/HTML/TUI reports. Admitting previously skipped
regex work can expose saturation at the existing cap. Off-frame raw matches
still consume that cap; an eligible occurrence after the cap stays unreachable.
This is an explicit coverage limitation, not grounds for raising a limit.
The role cases append one eligible marker after the repeated off-frame markers:
the case named `off_frame_unicode_roles_16` therefore has 17 raw occurrences.
Seven dense-input cases gain one saturation record each; all match the reference
in full, and the over-limit input is rejected identically by all configurations.

Warmed ordinary-prose scans cost **1.0–6.2%** more across 1, 16 and 128 KiB;
literal-dense nonmatching inputs cost **7.2–11.2%** more. A short, newly admitted
17-marker tool input rises from **43.83 µs to 78.07 µs** (+78.1%); its new match
work and saturation remain bounded. All 15 runtime cases match the reference
in full. Exact samples and large-input costs appear in the reports.

Corpus timing uses three sequential, rotating-order trials for baseline,
accepted and reference on one frozen release executable. Per-slice times include
scan and native result publication. Microbenchmarks use five rotating-order
warmed samples per case, with construction time separate. These are local
measurements, not latency guarantees; constructor figures for supplied engines
are not a cold-start measurement of shipping's lazy compiler. See the companion
reports for every sample, median and change percentage.

## Reproduce and independently recount

Frozen rule snapshots are included:
[baseline](matching-consistency-2026-09-15/baseline.toml),
[accepted](matching-consistency-2026-09-15/accepted.toml), and
[full corrections, including rejected changes](matching-consistency-2026-09-15/full-corrections.toml).
They prevent a future current-checkout build from silently selecting different
rules. Core source and executable hashes are recorded with the experiment.

From this source revision, with the existing frozen local corpora available:

```bash
cargo build --release --locked --offline --manifest-path crates/eval/Cargo.toml \
  --bin please-eval --example matching_consistency --example prefilter_runtime
mkdir .cache/matching-consistency-reproduction
cp docs/research/matching-consistency-2026-09-15/baseline.toml \
  .cache/matching-consistency-reproduction/baseline.toml
python3 crates/eval/scripts/detection_experiment/prepare_prefilter_corrections.py \
  .cache/matching-consistency-reproduction/baseline.toml \
  .cache/matching-consistency-reproduction
python3 crates/eval/scripts/detection_experiment/prepare_matching_consistency.py \
  .cache/matching-consistency-reproduction/syntax.json
python3 crates/eval/scripts/detection_experiment/run_matching_consistency.py \
  .cache/matching-consistency-reproduction
python3 crates/eval/scripts/detection_experiment/report_matching_consistency.py \
  .cache/matching-consistency-reproduction --tui
```

Use a new directory; the runner refuses to overwrite evidence. `shipping` mode
checks that the supplied accepted source equals the rules compiled into its
binary. A later rule change must use this preserved source revision to repeat
that comparison. Corpus locations and identities appear in
`experiment-identities.json`; the runner neither acquires new data nor silently
substitutes another split. Licensed upstream prompt text remains in the local
cache, not in the published reports. The earlier
[corpus report](detection-improvement-2026-09-14.md) describes the frozen-input
provenance; its historical email detector is not used here.

For the retained run, regenerate/recheck reports without rescanning:

```bash
python3 crates/eval/scripts/detection_experiment/report_matching_consistency.py \
  .cache/matching-consistency-20260915 \
  --check docs/research/matching-consistency-2026-09-15.json --tui
```

The reporter invokes the native saved-run verifier for every run, requires
completion, checks row checksums and input identities, recalculates counts and
multiset differences, and rejects a supplied report that differs. It verifies
repeatability, accepted/shipping equality and full-correction/reference equality.
Separate checksum-bound diagnostics compare full findings, suppression and gap
details. The local `row-deltas.json` retains every changed row ID and native
finding, with its digest in the public report. Recorded timing/diagnostic
sidecars are bound to their saved checksums, not independently remeasured by
the reporter. This verifies consistency, not authenticity against replacement
of an entire evidence package.

The experiment-specific TUI has dataset, rule, runtime, coverage-gap and notes
pages (Tab to switch, arrows to scroll, `q` to exit). The same derived tables
appear in `report.html` and `report.txt`; each underlying native run also keeps
its ordinary evaluator HTML report.

## Regression checks

```bash
cargo test -p please-core --test prefilter_consistency
python3 crates/eval/scripts/detection_experiment/test_matching_consistency_report.py
```

The core tests check every rule's effective probes, normal/shipping equality,
corrected-rule reference equality across syntax and carriers, the five deferred
benign conflicts, and unchanged raw caps/framing/quote suppression. The report
tests check finding multiplicity, corrupt totals and HTML escaping. The existing
native auditor regressions also cover corrupt result bytes, incomplete saved
runs and mismatched input/pipeline identities.

Validation completed: **643 workspace tests passed**, with 18 pre-existing ignored
tests; this includes all six matching-consistency tests. Workspace and experiment
Clippy checks passed with warnings denied, formatting checks passed, and the
shipping dependency allow-list remains exactly 27 crates. The native audit
regression and two report unit tests pass. The real report CLI also rejected a
copy whose accepted LLMail total was changed from 12,239 to 27,963 after
independently verifying all 21 runs. TUI tab navigation, horizontal scrolling
and exit were exercised in a real PTY. Local logs are retained in
`.cache/matching-consistency-20260915/`.
