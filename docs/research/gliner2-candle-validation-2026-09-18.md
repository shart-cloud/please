# GLiNER2 classification in Candle — September 18, 2026

The classification-only Candle implementation passes the pinned GLiNER2 reference checks.
The larger benchmark runs through PLEASE's existing `bench run` framework. No Python model
runtime is used during benchmark inference and no model was added to the shipping scanner.

| Check | Result |
|---|---|
| Synthetic score probes | 18/18 pass; includes two exact 512-token inputs |
| Token IDs and schema label positions | Exact for all 18 |
| Top labels and 0.7 threshold decisions | 18/18 match |
| Maximum absolute logit difference | 0.00003958; gate 0.001 |
| Maximum absolute probability difference | 0.000002206; gate 0.0001 |
| Additional seeded Unicode/punctuation tokenization probes | 128/128 exact |
| Native protocol boundary checks | Reserved markers, >512 tokens, and >16 KiB inputs abstain; zero API calls |

These checks establish agreement on the tested inputs, not full GLiNER2 feature compatibility
or accuracy. The adapter implements single-label classification with descriptions. It does not
implement entity/relation/span extraction, counting, training, or arbitrary GLiNER2 schemas.

The port loads the model's DeBERTa-v2 backbone and `classifier.0`/`classifier.2` linear layers,
with ReLU and softmax. Validation caught and corrected the reference collator's terminal-period
insertion and Python/Rust differences in Unicode case-insensitive email/handle matching.
The committed synthetic fixtures retain these regressions.

Model: `fastino/gliner2-base-v1` at `79c3a777abc572b4767922f3916cf63fb5754df2`.
Reference library: GLiNER2 2.0.0. Backend: Candle 0.11, CPU f32, four Rayon threads.
The model and library versions are separate identities. Asset hashes, frozen binary hashes,
and numerical results are in the accompanying JSON.

The 6,000 public and 600 contextual cases reuse the frozen Jev scale selection. The contextual
rows contain only 50 distinct candidate texts, so they are correlated regressions. These are
exploratory development data, with no independent holdout or score calibration. The 512-token
cap includes schema tokens and produces explicit abstention rather than truncation.

Implementation and reproduction: [Candle evaluation workflow](../../crates/eval/scripts/gliner2_candle/README.md).
Jev uses the native adapter over the same shared client as `plz jev` and `plz clap`;
see [bench usage](../../crates/eval/BENCH.md).
