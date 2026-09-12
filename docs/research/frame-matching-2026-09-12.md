# Frame-aware matching validation — 2026-09-12

Frame eligibility now belongs to the matcher for direct and decoded rule matches. Bounded raw
collection, quoting suppression, and original-input evidence attribution retain their behavior.
Direct matching reuses the frame metadata already computed for quoting; decoded candidates and
standalone matcher calls initialize metadata lazily for their own bytes.

## Correctness and integration

Characterization tests passed before refactoring. The final core suite passed 436 tests (7 normally
ignored), CLI suites passed 45, and evaluation product/boundary suites passed 6. Cases include caps
of zero/exact/overflow, off-frame hits consuming the cap, unanchored controls, quoting with zero
display limits, and multiple quoted encoded candidates with distinct original spans. Matcher tests
also exercise both public operations and compare their coverage events.

Clippy with warnings denied, WebAssembly compilation, formatting, core isolation, and the normal
dependency allow-list passed. Review found no correctness issue in eligibility or metadata reuse.
No live model or judge evaluation was involved.

## Release gates

| Measurement | Before | Final | Existing gate |
|---|---:|---:|---:|
| Input-length growth exponent | 0.932 | 0.939 | ≤ 1.15 |
| 4 KiB p95 latency | 0.509 ms | 0.602 ms | ≤ 10 ms |
| Sustained throughput | 11.6 MB/s | 8.3 MB/s | ≥ 8 MB/s |
| Payload-dense versus benign cost | Passed | Passed | ≤ 20× |

Both release-gate runs passed. These absolute times vary with the measurement environment. The
8 MB/s floor is not the historical 10 MB/s target, and the final run does not establish that target.

## Benchmark investigation and limits

Full benchmark runs used identical workloads, 1-second warmup, 1-second measurement, and 10 samples.
They included eligible and off-frame hits, JSON and whitespace-heavy inputs, decoded candidates,
full scans, and the existing individual pipeline stages. No other agent builds or tests ran during
measurements.

The first implementation repeated the direct JSON-shape probe. Timings flagged the relevant
workloads, so the final implementation reuses existing original-input metadata and removes that
extra work. Subsequent benchmark flags varied, including for unchanged decoding and structural
stages. Re-running the unchanged baseline also changed its timings materially.

To examine ordering effects, preserved before/final executables were run in three interleaved
pairs: before/final, final/before, before/final. These focused runs used 0.2-second warmup and
0.5-second measurement, with 10 samples and plots disabled. Ranges below are the point estimates
across the three runs, not confidence intervals:

| Workload | Before range | Final range |
|---|---:|---:|
| Eligible hits | 244.55–264.85 µs | 249.76–265.14 µs |
| JSON | 4.397–5.193 ms | 4.241–4.673 ms |

Those ranges overlap, and the apparent slowdown changes direction across pairs. The investigation
did not establish a consistent regression in these cases. It also does not establish a speedup or
prove universal performance equivalence. Preserve the raw results rather than selecting only the
favorable run. The JSON workload has an early key/colon; it does not separately measure late-colon
arrays. The final direct path nevertheless avoids a repeated document-shape probe for either form.

## Evidence

[Raw logs, source identities, executable hashes, and commands](frame-matching-2026-09-12.json)
retain the initial, intermediate, final, and repeated measurements. Sources were captured from the
working tree, including the preceding architecture changes; a Git HEAD alone would not identify
these builds.

- Before production source digest: `128a639ecf14a62d67db0a060bb4be6d1b20e23535ca15bc1fe5fd578850f3fe`
- Final production source digest: `7d8713dffbb7c46e39d5ca6ed13719681a93b7f6aa0e3d5d662805e93e2afed0`

The source digest is SHA-256 over the sorted mapping of production Rust paths to file SHA-256 values;
the complete mapping is in the JSON artifact. Temporary benchmark executables and logs remain in
`/tmp/please-frame-matching/`. No source changes followed the final correctness/performance build.
