# Decision semantics — September 11, 2026

Implemented the excerpt distinction and separately specified the proposed ML review contract.
No classifier threshold, detector rule, judge prompt, model, upstream label, or export permission
changed. The prepared pre-change judge comparison is preserved in an ignored source snapshot and
executable; its original frozen artifacts remain intact.

## Presentation-only implementation

`Reason::excerpt_truncated()` now records display shortening independently of incomplete analysis.
Both detector-side shortening and sanitization expansion set it. It survives quoting suppression and
judge demotion, is emitted in JSON when true, and is identified in human output. The original span,
severity, and model attribution are retained. The schema accepts the new optional field and historical
reports without it.

Current finalization no longer manufactures an `excerpt_length` coverage gap when it shortens a
displayed excerpt. It does not remove existing caller-supplied gaps. Skipped input, decode limits,
failed inference, missing findings, and unavailable tiers remain incomplete. A truncated reason list
still prevents safe judge rescoring. See [presentation metadata](../presentation-metadata.md) for
the compatibility contract.

The regression test first reproduced a fully demoted finding remaining `Inconclusive` solely because
its excerpt was short. It now becomes `Clean` after complete analysis, for both structural and ML
composition. Companion tests preserve genuine coverage gaps through demotion, retain presentation
metadata on suppressed reasons, and exercise early truncation, sanitization, direct/decoded matches,
JSON, and human output.

## Frozen-data comparison, without judge demotion

Reused the recorded model probabilities and reconstructed the candidate verdicts through production
structural scanning and finalization. All **600** candidate verdicts equal the original verdicts after
accounting only for the new display flags and removal of generated excerpt gaps. Both sets pass the
updated schema. No model inference was repeated.

| Original label | Block, before → after | Review, before → after | Allow, before → after | Incomplete cases, before → after | Cases with new display metadata |
| --- | ---: | ---: | ---: | ---: | ---: |
| Benign (300) | 63 → 63 | 11 → 11 | 226 → 226 | 49 → 0 | 49 |
| Injection (300) | 264 → 264 | 8 → 8 | 28 → 28 | 78 → 0 | 78 |

**Benign interruptions removed: 0/74. Caught attacks released: 0/264.** Benign interruption remains
74/300 (24.7%). In this pack, every affected input still has an active finding, so correcting
presentation metadata alone does not alter its block/review/allow decision. These are decision-semantics
results, not a detection-accuracy improvement or judge-clearance measurement.

All **346** assembled judge request hashes are identical before and after the presentation change;
the other 254 cases still have no findings. This permits a future comparison using the same captured
judge responses to isolate the presentation effect from model variation. The old artificial floor of
49 benign reviews after hypothetical universal demotion no longer follows from excerpt display alone.
That does not establish how many findings a real judge should or will demote.

This remains a DeBERTa direct-prompt experiment with caller source `untrusted_user_input` and no
application-specific export policy. It does not measure export detection, long-document reliability,
or fresh indirect/reference coverage.

## ML review contract, specified separately

The [ML boundary-review proposal](../../specs/006-local-ml-tier/contracts/ml-review.md) is versioned
`ml-boundary-review-v1-draft`; **it is not implemented or enabled**. It requires caller-owned origin,
task/permission context as needed, explicit instruction boundaries, and the complete document. Its
closed outcomes are `supported_violation`, `no_supported_violation`, and `indeterminate`.

Only a validated no-supported-violation response with sufficient host-established context may demote
the corresponding ML finding. The proposal requires a separate finalizer/type enforcing ML-only
eligibility; structural findings cannot be demoted through this route. Missing context, malformed
responses, invalid candidate references, and failed review remain incomplete. Ordinary requests and
unrelated prose can receive a no-supported-violation judgment without being forced into the existing
structural judge's instruction-description categories.

The contract specifies offline acceptance cases and four separate evaluation arms: original baseline,
presentation only, ML review only, and combined. Each tracks benign interruptions removed, caught
attacks fully allowed, block-to-review transitions, source breakdowns, and failures. Existing labels
remain unchanged. Live judge measurements are pending credentials and implementation of the new route;
they are not inferred from controlled test responses.

## Artifacts, reproduction, and validation

The [machine-readable comparison](decision-semantics-2026-09-11.json) records counts, transitions,
baseline/candidate identities, source hashes, and the contract-only status of ML review. Raw inputs
and verdict excerpts remain local and ignored.

- `.cache/dataset-evaluation-20260911/decision-baseline-01/`: 314 pre-change repository files with
  hashes, the original diagnostic executable, and a copy of its harness source/lockfile.
- `.cache/dataset-evaluation-20260911/presentation-01/`: candidate verdicts, measurements, request
  protocol, and aggregate summary.
- `.cache/dataset-evaluation-20260911/presentation-harness/`: separate offline comparison instrument;
  refuses differences beyond the specified presentation change and does not run the judge.

```bash
# Check the preserved pre-change implementation against its original frozen results.
.cache/dataset-evaluation-20260911/decision-baseline-01/dataset-diagnostic-harness prepare

# Reproduce the presentation-only comparison; no inference or judge calls.
cargo run --offline --locked \
  --manifest-path .cache/dataset-evaluation-20260911/presentation-harness/Cargo.toml \
  --target-dir target -- prepare
```

The original diagnostic harness compiled against current source should reject equality with the old
verdicts; that is intentional. Use the preserved executable for the old judge baseline. Before a live
paired experiment, capture the actual tool responses and request hashes through the client/parser seam
as specified in the contract, so presentation-only and combined arms can replay identical responses.

Validation includes the workspace suite, CLI feature configurations, ML composition checks, formatter,
Clippy, schema checks, frozen-package integrity, unchanged judge request hashes, and the preserved
baseline's full equality check. Live judge tests and real-weight inference were not run for this
finalizer-only correction. Existing absolute fixture release-quality criteria remain unmet.
