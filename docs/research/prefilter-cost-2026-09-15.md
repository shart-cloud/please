# Prefilter cost attribution and fresh holdout — September 15, 2026

[HTML report](prefilter-cost-2026-09-15.html) ·
[Verified machine record](prefilter-cost-2026-09-15.json)

## What changed

The [matching-consistency audit](matching-consistency-2026-09-15.md) recovered
2,251 generated syntax detections and left natural-dataset detections unchanged,
at a measured 12.8% runtime cost. This round attributes that cost before changing
any deferred rule.

The selected candidate compacts literal gates using specific fragments required
by the existing regexes, changing nine literal lists. For example, `ystem`/`yſtem` and `istant`/`iſtant` cover
the Unicode case variants of the role words with four literals. Complete action
verbs such as `send` remain intact. `forget_everything` gates on `everything`,
and `new_instructions_follow` gates on `instruction`/`inſtruction`.

No regex, severity, framing, suppression, decoding or policy changes are included.
High/enforcement remains in use, with the same 1 MiB input limit, three decode
levels, 16 raw matches per rule, 4,096 observations and 64 reported reasons.
The ungated reference remains test-only. The five deferred rules remain unchanged.

## Attribution: a shared threshold, not thirteen additive costs

The original role-marker baseline had **92 distinct literals**. The thirteen
consistency corrections increased that to **126**. The pinned `aho-corasick`
1.1.5 dependency automatically chooses a DFA at at most 100 patterns and a
contiguous NFA above that threshold (`src/ahocorasick.rs`, `build_auto`). These
are different matching implementations with different speed/memory tradeoffs.
The DFA uses a larger transition table; the NFA saves memory but can do more
work per input byte.

Adding only the Unicode role-marker correction takes the count from 92 to 102,
crossing that threshold by itself. Removing it from the full correction set
leaves 116, so the reverse measurement does not undo the same cost. The
[layout diagnostic](../../crates/core/examples/prefilter_layout.rs) reconstructs
the exact production builder and records its selected kind and memory use.
The shipping builder's automatic choice is unchanged.

Every correction was measured in both directions:

- Add it alone to the pre-audit baseline.
- Remove it alone from the full thirteen-rule correction set.

The workload uses at most 128 already exposed rows per development slice,
selected by a fixed salted content hash, plus ordinary prose and literal-dense
nonmatching text. Five warmed trials rotate configuration order and alternate
direction. Preparation is recorded separately. These sample weights are for
attribution, not population accuracy. Per-rule timing ranges, including negative
or noisy deltas, are retained in HTML/TUI/JSON. Costs are not additive.

### Candidate selection

The first broad fragment compactions recovered ordinary-prose speed but admitted
too much extra regex work on the corpus. In particular, replacing `send` with
`end` was counterproductive. Those candidates are preserved as rejected
performance alternatives.

The selected **specific-fragment candidate has 96 distinct literals**. In its
five-trial selection run, sampled corpus scan time fell from 716.79 ms to
635.60 ms, about 11.3%; the pre-audit baseline in the same run was 635.22 ms.
A dash-only delimiter gate offered no clear benefit over the more specific
word fragments, so it was not selected. These figures exclude native result
publication and must not be compared directly with full-corpus replay seconds.

Memory is an explicit tradeoff: the shared automaton grows from **39,192 bytes
to 386,676 bytes**, still below the pre-audit DFA's 403,912 bytes. Scan resource
limits are unchanged. A regression test exercises the real private prefilter
builder and catches an unexpected switch back to the slower automatic layout;
it failed before the change and passed afterward. Future rule additions must
revisit that measured cost explicitly.

## Deferred rules: five separate paired-control screens

Each candidate changed only one rule's literals. Four attack/ordinary-language
pairs per rule were written and frozen before scanning. Each side was evaluated
in original, uppercase and Unicode-case forms through plain text, JSON, HTML
comments, Markdown and base64: 60 attack and 60 ordinary rows per rule.
These are first-party scenario labels without independent review. Existing
ordinary-language findings are retained in the baseline; only additions decide
whether a broader gate can advance.

| Rule | Added target findings: attack | Added target findings: ordinary | Result |
| --- | ---: | ---: | --- |
| `solicitation.credentials` | 48 | 50 | Rejected |
| `solicitation.tool_enumeration` | 40 | 41 | Rejected |
| `boundary.forged_system_directive` | 37 | 39 | Rejected |
| `agent_directed.addressed_marker` | 29 | 30 | Rejected |
| `privilege.permission_widening` | 59 | 60 | Rejected |

The individual failure mechanisms are concrete:

- **Credentials:** “secret” includes secret Santa assignments; a credential can
  be a visitor badge. The key-path regex also accepts a private-key filename
  prefix in a `.pub` public-key path. Broader literals expose these existing
  regex decisions.
- **Tool enumeration:** enumerating an agent's tools and describing woodworking
  tools share the specified pattern. Severity 55 means both High detection
  totals can stay zero while new benign findings still appear.
- **System directive:** the zero-separator spelling also names an ordinary
  identifier. A colon-only refinement would still need to distinguish a typed
  declaration such as `systemoverride: boolean;` from forged authority.
- **Addressed marker:** “Messages for the assistant are stored in the inbox” is
  a mention rather than an address. The regex currently accepts both.
- **Permission widening:** documentation mentioning `bypass_permissions`,
  `auto_approve`, or how to disable a sandbox also satisfies the pattern.

None advanced to holdout evaluation. Their paired examples, native findings,
source hashes and individual rejected candidates are retained. Gate broadening
alone does not resolve these semantic distinctions. This round accepts the
performance correction only, rather than treating generated-case gains as
evidence of natural-language precision.

## Freeze and fresh holdout

The candidate rules, executable, verifier and relevant source files were frozen
before holdout acquisition. Pre-freeze full-verdict comparisons showed no
differences on the 103,968 syntax rows, 195 benign controls, all fourteen
development slices or the previously exposed 600-row validation package.
The candidate was not retuned after holdout outcomes were opened.

The holdout uses the previously pinned dataset revision
`Necent/llm-jailbreak-prompt-injection-dataset@4edfb5aeaafe58c9bf489a478a42188f239d7c1e`.
The exposure index conservatively includes previous unused overfetch, materialized
corpus packages, captures, manifests and authored controls: **180,412 exact
hashes and 126,295 normalized hashes**. Normalization is NFKC, case folding and
whitespace collapse. Source carrier templates with insertion markers are indexed
as raw text; materialized inputs are indexed separately.

Selection uses ascending content SHA-256 within six fixed source/label strata,
unchanged upstream adversarial labels, harmful=0, exact-label-conflict exclusion
and normalized deduplication. The initial target was 100 rows per stratum.
Gandalf-Ignore had only 87 usable rows after exclusions. A blinded expansion of
the overfetch from 400 to 4,000 confirmed exhaustion; all 87 were retained and
the other quotas stayed at 100. The final holdout is therefore **587 rows:
287 attack and 300 benign**. Both acquisition plans and the availability amendment
precede any detector outcomes and are preserved with their hashes and timestamps.

This is fresh relative to indexed local exposure, with zero exact or normalized
overlap. It is **within-source direct-prompt validation**, not a new-source or
fresh indirect-injection population. Unrecorded inspection, semantic paraphrase
overlap, training overlap and upstream label errors cannot be ruled out. Labels
do not establish application-specific task authorization. Prompt bytes stay in
the local cache; the public report includes only identities and derived evidence.

## Final replay and verification

**All native rows and full verdicts are preserved**, including all 2,251 syntax
detections recovered by the previous audit. No new benign findings, incomplete
scans or gap details appear. LLMail remains at 12,239 detections and 157 incomplete
rows; InjecAgent remains at 442 detections. The fresh holdout records **78/287
attack detections and 1/300 benign detections**, with zero incomplete scans,
identically for baseline and candidate.

Development scan-and-publication time improves from **21.13 s to 18.49 s
(−12.5%)**. Timing does not improve uniformly: the initial three holdout trials
measured **151.71 ms to 161.18 ms (+6.2%)**, with overlapping ranges of
134–228 ms and 145–179 ms. This uncertainty triggered one declared, fixed batch
of ten additional timing pairs on the now-exposed rows, using unchanged frozen
binaries. That confirmation measured **119.89 ms to 111.07 ms (−7.4%)**.
Both batches and all samples remain in the report; neither is another fresh
accuracy evaluation, and no candidate tuning followed either result.

The dense-literal microbenchmarks improve by 7.7–14.8%. Ordinary prose is mixed:
1 and 128 KiB improve about 6%, while the 16 KiB point estimate is 10.3% slower,
with overlapping sample ranges. These local measurements establish the large
development-workload gain; they do not establish a universal latency improvement.

The final reports contain detection totals, individual finding deltas, incomplete
scans and runtime for every development and holdout slice. Development and
holdout use three alternating-order baseline/candidate trials on the same frozen
release executable. Corpus timings include native result publication; construction
is separate. Shipping runs and full in-memory comparisons check findings,
suppression, transform chains and gap details beyond the saved row projection.
The ordinary/dense runtime suite retains all fifteen cases and every gap detail.

The reporter independently verifies completed native runs, checks input IDs,
sources, byte hashes, policy and source identity, recalculates counts/differences,
checks repeatability and verifies the freeze/acquisition/evaluation timeline.
A supplied report with altered totals is rejected. Recorded timings are verified
as recorded artifacts, not remeasured by the reporter. This establishes evidence
consistency, not authenticity against wholesale replacement of every artifact.

## Reproduce

Use the retained frozen binaries for this exact historical replay. Rule snapshots
are [baseline](prefilter-cost-2026-09-15/baseline.toml) and
[candidate](prefilter-cost-2026-09-15/candidate.toml). A future current checkout
can contain a different detector; `shipping` mode refuses a rule source that
differs from its compiled built-ins.

Recount and open the retained HTML/TUI evidence without rescanning:

```bash
python3 crates/eval/scripts/detection_experiment/report_prefilter_cost.py \
  .cache/prefilter-cost-20260915 \
  --check docs/research/prefilter-cost-2026-09-15.json --tui
```

Tab switches attribution, candidate-selection, dataset/holdout, corpus-runtime,
deferred-rule and runtime/gap pages; arrows scroll and `q` exits. The same tables
are saved as HTML and plain text.

The scripts record the complete workflow:

1. `prepare_prefilter_attribution.py` snapshots baselines and individual ablations.
2. `prefilter_attribution` runs five rotating-order timing trials;
   `prefilter_layout` records the builder's actual automatic choice.
3. `prepare_prefilter_candidates.py` creates the alternatives and the paired
   deferred-rule packages. Its baseline is the preserved pre-compaction source.
4. `freeze_prefilter_candidate.py` checks the selected source and pre-freeze
   equality evidence, then freezes the candidate. It refuses an existing freeze.
5. `fresh_prefilter_holdout.py plan/query/freeze` indexes exposure, acquires the
   pinned sample and checks exact bytes. The documented `expand` and `available`
   amendments handle the observed blinded availability shortage.
6. `run_final_prefilter.py` verifies the freeze, marks holdout exposure before
   scanning, runs the sequential native comparisons, and binds its sidecars.
7. `report_prefilter_cost.py` independently verifies and recounts results.

For an attribution replay on the preserved baselines (existing frozen local
corpora required), build the examples and use a new directory:

```bash
cargo build --release --locked --offline -p please-core --example prefilter_layout
cargo build --release --locked --offline --manifest-path crates/eval/Cargo.toml \
  --bin please-eval --example prefilter_attribution \
  --example matching_consistency --example prefilter_runtime
python3 crates/eval/scripts/detection_experiment/prepare_prefilter_attribution.py \
  .cache/prefilter-cost-reproduction \
  docs/research/matching-consistency-2026-09-15/accepted.toml
python3 crates/eval/scripts/detection_experiment/run_prefilter_development.py \
  .cache/prefilter-cost-reproduction
```

This replays the documented candidate choice rather than selecting a new winner
from timing noise. `freeze_prefilter_candidate.py` requires the shipping source
to match that selected candidate and retains the source and binary identities.
The timing-confirmation command is separately reproducible with
`confirm_prefilter_timing.py ROOT`; it requires a completed holdout evaluation
and always runs ten pairs without early stopping.

Use a new evidence directory for a new experiment and add this now-exposed holdout
to future exclusions. Replaying these 587 rows again is a regression check, not
another untouched holdout. Local evidence and logs live under
`.cache/prefilter-cost-20260915/`.
The Gandalf-Ignore stratum is now exhausted under this inventory; another fresh
round needs a new preregistered selection rather than silently recycling rows.

## Checkpoint validation — September 15 resumption

The retained-evidence reporter independently reverified all **51 native runs**
and matched the saved JSON before the missing public JSON, HTML and rule snapshots
were copied into this directory. The current built-in rules and every detector
source recorded in the candidate freeze match their frozen bytes. This check
recounts existing evidence; it does not claim another fresh evaluation or timing run.

The completed validation checks are:

- Workspace tests: **644 passed**, 18 pre-existing ignored, no failures. HTTP
  fixture tests were rerun outside the sandbox after localhost binds were denied.
- Excluded evaluator: **117 passed**; shipping judge/ML product and boundary
  integration: **6 passed**.
- Python experiment-report regressions: **6 passed**, including the retained
  evidence corruption check; holdout-selection regressions: **2 passed**.
- Workspace and evaluator formatting and all-target Clippy with warnings denied.
- Shipping dependency allow-list: exactly **27 crates**; core, CLI and ML
  isolation checks passed.
- Generated corpus reproduced exactly. The offline mechanism-mode regression
  gate passed its pinned baselines; this does not establish the separate 1% false
  positive criterion or a deployment accuracy claim.

The experiment-report Python tests now run in CI. Frozen source corpora and
binaries remain local; a checkout without those assets can run the ordinary Rust
and Python regressions but cannot independently replay the retained 51-run audit.
