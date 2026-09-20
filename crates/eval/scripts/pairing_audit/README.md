# pairing_audit — offline GLiNER2/Jev paired error audit

Joins the two completed September 18 public runs case-by-case and analyses their
disagreements, error mechanisms and composition operating points.

**Strictly offline.** No API calls, no inference, no weight downloads, no network. Reads
only frozen saved-run evidence:

- `.cache/framework-models-20260918/run-public/results.jsonl` (GLiNER2 / Candle)
- `.cache/jev-scale-20260918/run-public/results.jsonl` (Jev replay)

Both share pack digest `d2979c50…`; the join is exact on `case_id` + `input_sha256` and
the scripts assert this.

## Discipline enforced by these scripts

- Rows without saved scores (GLiNER2 input cap, Jev provider-contract failure) are never
  imputed. They stay misses in every denominator.
- Denominators are always the full 3,000 attacks / 3,000 benign.
- No policy reads a source id or an expected label.
- `faithfulness.py` must show zero mismatches before any threshold sweep is meaningful —
  it re-derives every recorded decision from the saved distributions.

## Scripts

| Script | Purpose |
|---|---|
| `extract.py` | join both runs → `paired-public.jsonl`, print paired sha256 |
| `faithfulness.py` | reconstruct recorded decisions from saved scores |
| `audit.py` | paired detector table, error taxonomy, per-source breakdown |
| `phase2.py` | operating points, compositions, cascade ceilings |
| `phase3.py` | Pareto frontier, recall at stated FP budgets |
| `phase4.py` | error-confidence bands, selective-gain decomposition |
| `summarize.py` | machine-readable `summary.json` |

Outputs land in `.cache/pairing-audit-20260919/`. Re-run preparation only into a new
output directory; never overwrite a recorded experiment.

Report: `docs/research/gliner2-jev-pairing-audit-2026-09-19.md`.
