# Local window-overlap development measurement — 2026-09-11

Compared 0, 63, 127 and 255 payload tokens of overlap on the same 47 frozen cases: 21 attack and
26 benign placements from seven authored seeds in four related groups. This is development evidence,
not an independent holdout or a population accuracy claim. Shipping overlap remains **zero**.

| Overlap tokens | Attacks detected | Benign flagged | Median scan | p95 scan | Model windows | Model tokens |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 0 | 21/21 | 6/26 | 4.35s | 7.16s | 147 | 57148 |
| 63 | 21/21 | 5/26 | 4.82s | 7.99s | 154 | 63903 |
| 127 | 21/21 | 5/26 | 5.03s | 9.17s | 158 | 71267 |
| 255 | 21/21 | 5/26 | 7.54s | 13.21s | 211 | 99096 |

Each case ran once per overlap after an explicit model warmup. The sweep ran sequentially with no
competing builds or inference tests from this session. Latencies are descriptive across these document
lengths; there were no repeated timing trials or randomized run order. Counts and grouped exploratory
bootstrap intervals are in the machine-readable results. Related placements are not independent samples.

## Configuration and artifacts

- Model: ProtectAI DeBERTa-v3-small, revision `d7c8842daf06de3179cc3aca76b7b3a057acc5e7`.
- CPU/F32, context 512 tokens including two special tokens; payload capacity 510.
- ML admission threshold 700/1000; assessed impact 75; enforcement profile and shipping action threshold.
- Work limits: 4096 windows and 2097152 total model tokens. No requested remote judge.
- Runtime: Linux x86-64, eight available CPUs. Peak process RSS is recorded per run, including the harness.
- Suite SHA-256: `01657a868311fe5e88a9494d3c8c276ef70a5e052b738530a67ec903b3a9eb4f`.
- [Committed seed manifest](../../crates/eval/corpus/boundary/seeds.json) and [reproduction instructions](../../crates/eval/BOUNDARY.md).
- [Run summaries and paired changes](window-boundary-results-2026-09-11.json).
- [Per-case window evidence](window-boundary-rows-2026-09-11.jsonl). Input paths in these rows are relative to the regenerated suite directory.
- Full suite bytes, configuration files and unabridged reports: `/tmp/bee-boundary-measurement/`.

## Findings and limits

Zero overlap classified the reference control in the final window as malicious: two 510-token windows
scored 238/1000, but the final 20-token window scored 1000/1000. The added per-window evidence exposes
which context produced the document maximum. The 127- and 255-token runs removed that reference
false positive while all five long-document placements still flagged. The 63-token run instead
removed the long document’s final-placement false positive and retained the reference false positive.
Equal aggregate counts therefore do not mean identical decisions; the paired JSON records each change.

A discarded v1 pilot used repeated `word` padding and flagged all 26 benign placements. A carrier-only
probe scored that padding 999/1000, ordinary inventory prose 238/1000, and the bare translation control
388/1000. The final v2 suite uses the prose carrier, records it in the manifest, and verifies token
placement after joining the complete document. The v1 overlap sweep was stopped after its baseline;
no unfinished pilot comparison is counted here. This development correction further rules out treating
these fixtures as unseen validation data.

No operating point is approved from this experiment. The false-positive target is not established,
the corpus has only four related groups, and product runtime budgets have not been supplied. Keep the
current zero-overlap default. A future selection needs frozen numeric accuracy and resource criteria,
adequate independent held-out groups, and a separate threshold experiment if admission is retuned.
Window-scoped release decisions are also outside this measurement; review still uses the full document.
