# Hugging Face product benchmark — 2026-09-14

## Recorded result

Run: `hf-product-high-20260914-01`.

The shipping structural detector was evaluated on 32,017 cached rows verified against committed
manifests before scanning and again after recording. No ML model or remote judge was used.

| Slice | Rows | Detections / false positives | Rate | Distinct incomplete rows |
|---|---:|---:|---:|---:|
| InjecAgent | 1,054 | 442 detections | 41.9% | 0 |
| LLMail-Inject | 27,963 | 11,263 detections | 40.3% | 154 |
| OR-Bench | 3,000 | 0 false positives | 0.0% | 0 |

Rates use all supplied rows and integer per-mille rounding. They are per-slice results, not a pooled
accuracy score. The saved run is **complete**, with 3/3 slice result files verified and no integrity issues.
Saved-file completeness is distinct from coverage within an individual scanned row.

## Configuration and provenance

- Mode: product; profile: enforcement; threshold: High; quoted instructions remain active.
- Provenance: unspecified, matching the shipping default. Dataset source names do not invent trusted
  caller context.
- Rule set: builtin; recorded ruleset digest: `3b946803b23151d5`.
- Dataset: `Necent/llm-jailbreak-prompt-injection-dataset`.
- Pinned revision: `4edfb5aeaafe58c9bf489a478a42188f239d7c1e`.
- Detector source: commit `90f5676`; no changes to core, scan, or rules were made for this measurement.
- The run used the optimized release binary. Report changes were added locally and remain uncommitted.
- Raw corpus text stays in the local ignored cache.

The [machine-readable record](hf-product-high-2026-09-14.json) contains the metrics and input/result
SHA-256 checksums. The local presentation bundle also retains gate output, input-verification output,
the reporting source patch, and new presentation sources.

## Coverage and gate interpretation

LLMail has 154 distinct rows with at least one coverage cause: 151 maximum-match entries, 3 decode-depth
entries, 1 decoding failure, and 1 maximum-observation entry. These 156 entries overlap. Of the 154
affected rows, 25 still produced detections. They remain in the numerator and denominator as recorded;
the remaining rows must not be described as fully analysed clean inputs.

Recording this run exposed a reporting bug: the old known-gaps summary summed cause entries and called
that a row count. The updated summary counts each affected row once. It changes no detector decisions.
The initial derived reports remain in the run root for traceability; use the corrected
`presentation-v2/report.*` files.

OR-Bench meets the 1% false-positive criterion. The **default regression gate fails** (exit 2), because
the product-mode OR-Bench baseline is unpinned. This is a baseline-establishing measurement; no baseline
was pinned and no gate requirement was relaxed.

These public rows have been used in earlier development. They are not a fresh independent holdout or
deployment accuracy estimate. This run measures artifact detection, not contextual alignment.
None of its 29,017 positive rows has an upstream technique label, so the technique tab cannot establish
per-technique effectiveness. Historical Low/reference-analysis measurements have different operating
points and must not be presented as directly comparable to this High/enforcement run.

## Files and reproduction

Saved run directory:

```text
/home/jg/.cache/please-eval/results/hf-product-high-20260914-01
```

Corrected HTML, JSON, Markdown, and evidence bundle:

```text
/home/jg/.cache/please-eval/results/hf-product-high-20260914-01/presentation-v2/
```

Windows-accessible copies:

```text
C:\Users\jg\benchmark-preview\hf-product-high-20260914-01\
```

From the repository root, reopen the recorded results:

```bash
cargo run --release --manifest-path crates/eval/Cargo.toml -- view \
  --run hf-product-high-20260914-01
```

To repeat the measurement, verify the cache and use a new label:

```bash
cargo run --release --manifest-path crates/eval/Cargo.toml -- manifest \
  --slice pos_injecagent --slice pos_llmail --slice neg_orbench
cargo run --release --manifest-path crates/eval/Cargo.toml -- run \
  --mode product --run hf-product-high-next \
  --slice pos_injecagent --slice pos_llmail --slice neg_orbench --tui
```

The new run automatically saves HTML, JSON, and Markdown, plus the existing immutable per-row evidence.
