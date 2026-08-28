# Phase 0 Research: the local ML tier

**Feature**: `006-local-ml-tier` | **Date**: 2026-08-26

Architecture decisions live in [plan.md](./plan.md). This document records the things that had to be
**measured or looked up** rather than reasoned about.

---

## R1 — Candle: dependency size, wasm32 support, and `unsafe`

**Decision**: `candle-core` + `candle-nn` + `candle-transformers` as the inference runtime, in a new
`crates/ml` crate that `please-core` never depends on.

### Measured (T001)

**Machine**: 12th Gen Intel Core i9-12900HK, 4 cores / 8 threads, 19 GiB RAM, Linux 6.6 (WSL2),
`rustc`/`cargo` 1.96.0. Counts are `cargo tree -e normal` resolved for `x86_64-unknown-linux-gnu`,
deduplicated by name and version, excluding the probe root.

| Dependency specification | Crates (CPU only) | `tokio` | `unsafe` |
|---|---:|---|---|
| `candle-core` default features | **119** | no | **yes** (SIMD, raw pointer arithmetic) |
| `candle-core` + `candle-nn` + `candle-transformers` | **129** | no | yes |
| the above + `tokenizers` (`onig`, no default features) | **129** | no | yes |
| the above + `candle-onnx` | **134** | no | yes |
| `candle-core` with `cuda` feature | **122** | no | yes |
| `candle-core` with `metal` feature (`aarch64-apple-darwin`) | **136** | no | yes |
| `candle-core` default features (`aarch64-apple-darwin`, for comparison) | 124 | no | yes |

**The estimates in the first draft of this table were low by roughly a factor of three** — ~35 against
a measured 119, ~42 against 129. Recorded rather than quietly corrected, because the estimate is what
the decision to isolate the tier was originally argued from, and the measurement makes that argument
stronger rather than weaker.

Adding `tokenizers` costs nothing because `candle-transformers` already depends on it. That is the fact
`crates/eval/Cargo.toml` pins the tokenizer line for: matching the version means one copy resolves, not
two.

What the numbers mean for this repository:

| build | crates | binary | clean release build |
|---|---:|---:|---:|
| `please-cli` — the shipping binary | 69 | — | — |
| `please-eval` default | 49 | 5.48 MiB | 30 s |
| `please-eval --features ml` | **161** | **11.97 MiB** | **149 s** |

The `ml` feature adds **112 crates**, 6.5 MiB of binary and 119 seconds of clean build — a dependency
graph 1.6× the size of the entire shipping CLI's, for an opt-in experiment. `target/` grows from 124 MB
to 499 MB.

No `tokio` in any configuration, as expected. `rayon` does arrive, via `tokenizers` — a thread pool
rather than an async runtime, but worth naming since "no async runtime" and "no threading" are different
claims and only the first is true.

### The `unsafe` constraint

`please-core` is `#![forbid(unsafe_code)]` and that is load-bearing — a detection engine is the wrong
place for it. Candle uses `unsafe` internally for SIMD, pointer arithmetic in tensor operations, and GPU
kernel bindings.

**Consequence**: the ML tier MUST live in its own crate. `please-core` MUST NOT depend on it. The
dependency direction is `please-ml → please-core` (for the observation and verdict types), never the
reverse. This mirrors `please-judge → please-core`.

### wasm32 support — measured (T001)

Candle has a `candle-wasm-examples` directory and a `candle-wasm-tests` crate, and BERT, T5 and Phi have
shipped wasm demos on Hugging Face Spaces. The first draft of this section concluded from that that
"`candle-core` builds for `wasm32-unknown-unknown` with the CPU backend".

**It does not, as stated.** Built against `wasm32-unknown-unknown` with default features, `candle-core`
fails:

```
error: The wasm32-unknown-unknown targets are not supported by default; you may need to
enable the "wasm_js" configuration flag.
  --> getrandom-0.3.4/src/backends.rs:194:17
```

It builds under two conditions, both of which the *caller* must supply:

1. `getrandom = { version = "0.3", features = ["wasm_js"] }` as a **direct** dependency — a transitive
   edge cannot enable it.
2. `RUSTFLAGS='--cfg getrandom_backend="wasm_js"'`. The feature alone is insufficient; `getrandom`'s own
   error says so.

With both, `candle-core` builds for wasm32 in 33 s (debug).

The full inference stack needs a third condition. `candle-core` + `candle-nn` + `candle-transformers` +
`tokenizers` with the `onig` feature **fails**:

```
error: failed to run custom build command for `onig_sys v69.9.3`
```

`onig_sys` is a C library with a build script, and there is no wasm32 C toolchain in the loop. Selecting
`tokenizers` with `features = ["unstable_wasm"]` instead of `onig` builds the whole stack in 39.6 s.

**Consequences**:

* SC-609 is achievable, and it is a **three-condition** gate rather than a property Candle has on its
  own. `ci/check-ml-wasm32.sh` (T042) must set `RUSTFLAGS` explicitly, or it will fail in a way that
  looks like Candle's fault.
* `please-ml` must select `tokenizers` features per target — `onig` natively, `unstable_wasm` under
  `[target.'cfg(target_arch = "wasm32")'.dependencies]`. Note that `crates/eval/Cargo.toml` deliberately
  uses `onig` to match `candle-transformers`; that choice is correct for the harness and wrong for the
  browser, and the shipping crate needs both.
* **Model weights must still be loaded by the caller**, not by the crate, since wasm has no filesystem.
  This is the same design `please-core` uses for rule sets: the crate takes bytes, the caller provides
  them.

### ONNX alternative

Candle also has `candle-onnx` for loading ONNX models. An ONNX export of Prompt Guard 2 86M exists
(`gravitee-io/Llama-Prompt-Guard-2-86M-onnx` on Hugging Face). `parry-guard` benchmarks ONNX at ~5–6×
faster than native Candle on Apple Silicon. Both backends should be feature-gated.

**Decision**: support both backends behind features. `--features ml-candle` for pure Rust portability,
`--features ml-onnx` for performance. Default: neither — the default binary is unchanged (FR-601).

---

## R2 — Models: what exists, what each costs, what each buys

### Classifiers (binary: malicious / benign)

| Model | Params | Size on disk | Architecture | Latency (CPU) | Multilingual | Source |
|---|---|---|---|---|---|---|
| ProtectAI/deberta-v3-small-prompt-injection-v2 | 44M | ~254 MB (f32) / ~90 MB (f16) | DeBERTa v3 | ~50–70ms per 256-token chunk (ONNX) | no | ProtectAI |
| meta-llama/Llama-Prompt-Guard-2-86M | 86M | ~344 MB (f32) / ~172 MB (f16) | mDeBERTa-base | ~150ms per 512-token chunk (Candle) | **yes** (8 languages) | Meta |
| meta-llama/Llama-Prompt-Guard-2-22M | 22M¹ | ~70 MB | DeBERTa-xsmall | ~20ms per chunk | limited | Meta |
| StackOne custom (MiniLM-L6 scale) | ~22M | ~22 MB | MiniLM-L6 | ~20ms | no | StackOne |

¹ Named for the backbone; the shipped model is reportedly ~70.8M parameters.

### Embedding models (for segment-level semantic analysis)

| Model | Params | Dims | Latency (CPU) | Candle support |
|---|---|---|---|---|
| sentence-transformers/all-MiniLM-L6-v2 | 22M | 384 | ~15ms per segment | via BERT arch |
| BAAI/bge-small-en-v1.5 | 33M | 384 | ~20ms per segment | via BERT arch |
| jinaai/jina-embeddings-v2-small-en | 33M | 512 | ~25ms per segment | candle-transformers has JinaBERT |

### What each tier buys

| Approach | What it catches that the structural tier does not | What it costs |
|---|---|---|
| DeBERTa classifier on every segment | Novel phrasing — the sixteen unreachable payloads | ~70ms per chunk, ~254 MB model, no determinism |
| Prompt Guard 2 on every segment | Same, plus multilingual attacks | ~150ms per chunk, ~344 MB model, Llama license |
| Embeddings + outlier detection | Instruction-data separation (the BIPIA problem, the seam) | ~15ms per segment, ~22 MB model, deterministic |
| Ensemble (classifier + embeddings) | Both of the above | Sum of costs |

### Prior art: parry-guard

`parry-guard` (MIT, 44 stars) already runs DeBERTa and Prompt Guard 2 via Candle or ONNX in Rust. It
is a Claude Code hook scanner, not a library. Key architectural observations from reading its code:

- **Chunking strategy**: 256 chars with 25 overlap, head+tail for long texts. This is the same sliding
  window approach Prompt Guard 2's documentation recommends (512 tokens, max-score pooling).
- **Daemon architecture**: model stays loaded in a background process, scans over IPC. Cold start ~580ms
  (ONNX) / ~1s (Candle). Subsequent scans hit the loaded model.
- **Backend toggle**: compile-time feature gate, not runtime. `--features candle` vs `--features onnx-fetch`.
- **Threshold**: configurable per invocation, default 0.7.
- **Text chunking is naive**: character-based, not token-based. A token-based chunker would avoid splitting
  mid-word.

**What PLEASE does differently and should preserve**: the structural tier runs first, the ML tier arbitrates
or extends. parry-guard runs ML on everything; PLEASE can be selective — run ML only on segments the
structural tier flagged OR on segments the DocumentMap register flags as anomalous. This is the difference
between a ~$70ms tax on every scan and a ~$70ms tax on suspicious inputs.

---

## R3 — Embedding-based outlier detection: measured

### The hypothesis

A segment whose embedding is semantically distant from its sibling segments is anomalous. In the
DocumentMap framework, "sibling segments" means segments of the same `SegmentKind` in the same document.
The cosine distance from a segment to its nearest sibling is the anomaly score.

### Why this is novel for this architecture

Existing prompt injection classifiers (DeBERTa, Prompt Guard) answer a binary question about each
segment independently: *is this text malicious?* The embedding approach answers a **relational** question:
*does this segment belong with the others?* That is the BIPIA signal — "recommend a good book" is not
malicious in isolation, but it is anomalous inside a table of employee records.

### The arithmetic

All of this is Candle tensor operations on CPU:

1. Tokenize each segment (HF `tokenizers` crate, already Rust).
2. Forward pass through a small BERT model (Candle `BertModel`).
3. Mean-pool the hidden states to get a 384-dimensional embedding.
4. Compute pairwise cosine similarity within each sibling group.
5. The segment with the lowest mean similarity to its siblings is the outlier.

Steps 1–3 are **34 ms** per segment for MiniLM-L6 — measured in R6 (T005), against the ~15 ms this
line originally estimated. Steps 4–5 are microseconds.

### Results (`docs/research/embedding-outlier-results.md`)

Model `all-minilm-l6-v2` at revision `1110a243fdf4`. 951 rows scored out of 1,060 (52 excluded for
`span_outside_every_segment`, 57 for `too_few_siblings`).

**Headline**: top-1 55.6%, top-3 80.3%. Verdict: **continue**.

The defining split is **isolated vs diluted**:

| stratum | rows | top-1 | top-3 |
|---|---:|---:|---:|
| isolated (payload in own segment) | 724 | 68.9% | 89.1% |
| diluted (payload shares segment) | 227 | 13.2% | 52.4% |

**Interpretation**: the embedding model works. The segmenter is the bottleneck. When the segmenter gives
the ranker a clean candidate, top-1 is 68.9% and clears every threshold. When the payload is diluted with
carrier text, the embedding of the mixed segment is pulled toward the carrier and the outlier signal is
lost. Improving the DocumentMap segmenter to produce more isolated segments is the highest-leverage path.

Weak carriers (`json-tool-result` 0%, `email-vendor` 5%, `package-manifest` 10%) are structurally
heterogeneous — their siblings are already dissimilar to each other, so the injection does not stand out.
Per `document-map.md` §6 M3, a signal that only works on uniform carriers is a rule about that format.
The classifier is the primary signal for heterogeneous contexts.

Strong carriers (`ci-log` 100%, `grep-output` 100%, `shell-transcript` 66.1%) are uniform — an
instruction among data lines is semantically alien. This is the embedding's sweet spot, and it is not
duplicable by a rule (the vocabulary of the injected instruction varies).

### The determinism question

**BERT inference on CPU with the same weights is deterministic**, unlike LLM text generation. There is no
sampling, no temperature, no top-p. The forward pass is matrix multiplication, layer norms, and softmax
— all of which produce identical results for identical inputs on the same hardware. Cross-platform
determinism (x86 vs ARM) depends on floating-point behaviour, which is NOT portable in IEEE-754 for
transcendentals — but cosine similarity of mean-pooled embeddings is addition, multiplication, and
division, all of which are portably specified.

**Consequence**: the embedding-based outlier score CAN be deterministic (SC-011 compatible) if quantized
to fixed-point after computation. The f32 intermediate values may differ across platforms; the quantized
score does not, for the same reason the structural tier's integer arithmetic does not.

### Kill criteria and status

Borrowed from `docs/research/document-map.md` §6: below 50% top-1 overall kills the approach. Measured
at 55.6% — **above the kill line, below the ship line**. The spec's SC-603 is split: isolated segments
pass (68.9% ≥ 60%), diluted segments are marginal (52.4% top-3 ≥ 50%). The path forward is better
segmentation, not a different embedding model.

### Measured (T006)

`all-MiniLM-L6-v2` at revision `1110a243fdf4`, mask-aware mean-pooled and L2-normalized, scored against
sibling segments with T014's `1000 - mean_cosine * 1000` quantized to `u16`. 951 of the 1,060 rows were
scoreable; the excluded 109 and every stratum are in
[`docs/research/embedding-outlier-results.md`](../../docs/research/embedding-outlier-results.md).

| criterion | stated in | measured | verdict |
|---|---|---|---|
| top-1 ≥ 60% | SC-603 | **55.6%** (529/951) | **continue** — above the 50% abandon line, below the 60% ship line |
| top-3 ≥ 60% | `document-map.md` §6 M1 | **80.3%** (764/951) | **passes** |
| works on more than one carrier | §6 M3 | 11 of 14 carriers ≥ 45% top-1 | **passes** |

Reproduce with `please-eval model outlier`; `--dry-run` reports what the segmentation reaches with no
model at all.

**SC-603 and M1 are not the same criterion.** SC-603 says the injected segment must be the *top*
outlier; `document-map.md` §6 M1 says *top-3*. The spec cites the memo as though they agreed. They do
not, and on this corpus they disagree about the answer — which is exactly why both are reported and
neither is quoted alone. Reconciling them is a decision for the spec, not for the harness.

### What the number actually says

**The binding constraint is segmentation, not the embedding.** Split by whether the payload became a
segment of its own:

| placement | rows | top-1 |
|---|---:|---:|
| `isolated` — the payload is its own segment | 724 | **68.9%** |
| `diluted` — the payload shares a segment with carrier text | 227 | **13.2%** |

On isolated payloads the signal clears SC-603's 60% comfortably. The aggregate 55.6% is those two
populations averaged, and it is the least informative number on the page. What the embedding cannot do
is find a payload *inside* a segment; what it does adequately is pick the odd segment out. That is a
statement about `SegmentKind` granularity — the thing `DocumentMap` would own — rather than about
MiniLM.

`positions.toml` is where this becomes concrete: `prepend` 82.8% and `trailing` 82.7% (own paragraph),
against `first-paragraph` 0.0% and `mid-paragraph` 35.9% (spliced mid-line). §6 already declared
position sensitivity a finding rather than a kill criterion, so this does not kill anything — but the
0.0% is worth naming plainly rather than letting it average away.

**JSON is the honest failure, and it is the useful output.** `json-tool-result` scores 0% top-1 and
`package-manifest` 10%; 52 of the 109 excluded rows are the same two carriers with the payload landing
outside any scalar field. A `"note": "<payload>"` is a short string among short strings, and it is not
semantically distant from `"Warehouse 4"` the way a paragraph of instructions is distant from a
paragraph of prose. This is §7's promised consolation prize: when the answer is not a clean yes, the
experiment produces the list of carriers that defeated it, which is the specification for what a model
would have to be good at.

### Sub-segment granularity — measured, and it makes things worse

The obvious reading of the placement split above is *"cut prose finer and the diluted population
becomes isolated"*. `spec.md` US2 drew exactly that conclusion. It is testable with one flag —
`model outlier --sentences` re-cuts `Prose` and `SignatureBlock` at sentence boundaries and changes
nothing else — and it is **false**.

Over the 951 rows scored under both granularities, same model, same scoring, same corpus:

| granularity | top-1 | top-3 | mean sibling group |
|---|---:|---:|---:|
| paragraph | **55.6%** | **80.3%** | 7.4 |
| sentence | 51.9% | 78.1% | 8.4 |

28 rows were fixed by the change and **63 were broken** by it. By position, where it helped and where
it hurt:

| position | paragraph | sentence | delta |
|---|---:|---:|---:|
| `post-signature` | 27.5% | 32.5% | **+5.0** |
| `mid-paragraph` | 35.9% | 38.7% | **+2.8** |
| `first-paragraph` | 0.0% | 1.2% | +1.2 |
| `list-item`, `table-cell`, `json-field` | — | — | 0.0 (not cut) |
| `post-gap` | 55.0% | 47.5% | **−7.5** |
| `prepend` | 82.8% | 74.1% | **−8.7** |
| `trailing` | 82.7% | 71.9% | **−10.9** |

It helps exactly where predicted — the diluted positions — and by two to five points. It hurts far more
on the positions that were already isolated, and those are the majority.

**The mechanism, and it is the finding.** `isolated` rows dropped from 68.9% to 63.8% even though
"isolated" means the same thing in both runs and those payloads were already segments of their own.
Nothing about the payload changed; its *siblings* did. `email-vendor` goes from 10 segments to 14, the
payload's sibling group from 5 to 9, and its rank from 1 to 2 — not because it became less distinctive,
but because four more short prose fragments joined the group and each of them is also unlike the group's
mean.

So the outlier score is not bounded by **payload isolation**. It is bounded by **sibling homogeneity**.
At paragraph granularity the payload stands out partly for being a short, imperative block among long,
discursive ones; cut everything into sentences and that contrast is the first thing to go. Finer
segmentation raises the noise floor faster than it raises the signal.

This is worth stating plainly because it inverts the cheapest available plan. "Improve the segmenter"
is not a path to a better outlier score — not in the direction of *finer*, which is the direction that
was assumed. A segmenter that made **siblings more homogeneous** would be a different proposal and this
measurement says nothing for or against it.

### M2 and M7 — the detector question, and it fails

M1 asks *can we find the seam*. `document-map.md` §4 asks a prior question first, and the SC-603 work
skipped straight past it: **M2 — is it a detector or a coin?** The document's own outlier score is the
highest any of its segments reaches, and M2 is the true-positive rate at the threshold where the matched
negatives produce no false positives. It needs no span label, which is why it — unlike M1 — could be run
on the held-out fixtures today.

Full report: [`docs/research/embedding-separation-results.md`](../../docs/research/embedding-separation-results.md),
from `please-eval model holdout`.

| slice | label | scored | min | p25 | median | p75 | max |
|---|---|---:|---:|---:|---:|---:|---:|
| `gen_positive` | positive | 1030 | 603 | 888 | **917** | 954 | 1048 |
| `gen_matched_negative` | negative | 13 | 694 | 817 | **892** | 932 | 1002 |
| `fix_positive` | positive (held out) | 20 | 601 | 826 | **864** | 891 | 980 |
| `fix_benign` | negative (held out) | 19 | 792 | 829 | **901** | 924 | 1003 |
| `repo_prose` | negative (held out) | 55 | 784 | 878 | **894** | 911 | 957 |

**The populations do not separate.** Positive and negative medians are 917 against 892 on generated
text, and 864 against 901 on hand-written text — where the *negatives score higher than the positives*.
Every quartile overlaps every other.

| metric | criterion | measured | verdict |
|---|---|---:|---|
| M2, zero FPR on 14 matched negatives | ≥25% (§6) | **3.1%** (32/1030) | **abandon** |
| M2, zero FPR on all 90 negatives incl. security prose | ≥25% (§6) | **2.9%** (30/1030) | **abandon** |
| M7, same threshold, held-out fixtures | — | 0.0% (0/20) | uninformative — see below |

**M7 is uninformative here, and saying so is the honest reading.** It went 3.1% → 0.0%, which is not a
cliff because there was nothing to fall off. A held-out check tells you whether a signal transfers; it
cannot manufacture one. §5.1's warning about fitting our own generator is not answered by this run — it
is *moot*, because the thing that might have been overfitted does not work on the generated data either.

**Why it fails, and it is not the model's fault.** Every document has a most-unlike-its-siblings
segment. A carrier with no payload at all still has one — its own oddest paragraph — and it scores about
as high as an injected one does. The outlier score is a *ranking* statistic that was being asked to serve
as a *magnitude*, and it does not carry that information. M1 measured the ranking and got 55.6%; M2
measured the magnitude and got 3.1%. Both numbers are about the same score and they are not in tension.

**One caveat that limits how hard M7 can be pushed at all**: 31 of the 51 injection fixtures were
unscoreable, because they are a sentence or two long and never reach two comparable segments. The
held-out positive population is 20 documents. That is a property of the fixture set rather than of the
model, and it caps what any held-out check can currently say.

### Consequence for the plan

Not abandoned, not yet justified. T013–T015 (the embedder, the outlier score, the corroboration rule)
are not cancelled and are not cleared to ship either. What would move it either way, in cost order:

1. ~~**Sub-segment granularity.**~~ **Tried, and it fails** — 55.6% → 51.9%. See the section above.
   The cheapest plan is spent, and it took one flag to find out, which is the argument for building the
   knob rather than reasoning about it.
2. ~~**M7, the held-out check.**~~ **Run, and it changed the question.** M2 — the detector metric M1
   presupposed — is **3.1%** against §6's 25% floor, and the positive and negative score distributions
   overlap at every quartile. §6's response to that is *abandon rather than tune*.
3. **A structural answer for JSON.** The two failing carriers may simply not be embedding-shaped.
4. **Span-label the fixtures**, if M1 is to survive in the corroborator role below. 51 injection
   fixtures, no `injected_span` on any of them, and M7's M1 half cannot be computed without one. It
   would also give the shipped detectors a held-out span-localisation number, which `metrics.rs`
   already knows how to compute and has never had.

### Where this leaves the embedding score

Three numbers, none of them in tension, and they do not all point the same way:

* **As a detector, it is dead.** M2 3.1% against a 25% floor, negatives scoring as high as positives,
  and §6 says abandon rather than tune. Nothing here is a threshold that was set badly.
* **As a localiser, it is mediocre but real.** M1 55.6% top-1 and 80.3% top-3 — given that a document is
  already suspect, the score points at the right segment more often than not.
* **The spec never asked it to be a detector.** D4's corroboration requirement already says the ML tier
  never acts alone: the classifier decides, the outlier score corroborates. M2 failing is fatal to a
  standalone embedding tier and not, on its own, to that narrower job.

Which of those §6's kill criterion governs is a **specification decision, not a measurement**. §6 was
written for the detector framing and it is unambiguous within it. What the measurement can say is that
the standalone version is finished, and that anything kept should be kept explicitly as corroboration
with M2's failure written next to it.

---

## R4 — Tokenization: the `tokenizers` crate

**Decision**: use the HF `tokenizers` crate (already pure Rust, already in the Candle ecosystem).

| | |
|---|---|
| Crate | `tokenizers` 0.21+ |
| Language | Pure Rust, no Python |
| wasm32 | builds (used in Candle's wasm examples) |
| Vocab loading | from a `tokenizer.json` file (the caller provides bytes) |
| Dependency count | ~12 crates |

The tokenizer is loaded from the same model directory as the weights. No separate download, no separate
configuration. `BertModel` and `DeBERTaModel` each have a paired tokenizer in their HF repos.

---

## R5 — Weight format and loading

### SafeTensors

Candle's primary weight format is SafeTensors (`.safetensors`), which is also the HF standard. SafeTensors
is a zero-copy memory-mapped format — weights are loaded by `mmap`ing the file, with no deserialization.
This is what makes cold start fast (parry-guard measures ~580ms including tokenizer init).

### Quantization

For edge deployment (Cloudflare Workers, WASM), quantized weights are essential. Candle supports GGML
quantization (the llama.cpp format). A 22M-parameter model quantized to 4-bit is ~11 MB — small enough
to embed as a `const` or to distribute alongside the binary.

**Not decided yet**: whether to ship weights embedded in the binary or require a model directory. Embedded
is simpler for the user but makes the binary ~22–90 MB larger. A model directory is the parry-guard
approach and keeps the binary lean. The spec leaves this to implementation.

### HF Hub download

The `hf-hub` crate provides authenticated download from Hugging Face. This is a build-time or first-run
dependency, not a scan-time one — once the model is cached locally, no network is needed. Feature-gated
behind `--features ml-download`.

---

## R6 — Latency budget and selective inference

### The problem

Running a classifier on every scan adds ~70ms (ONNX) to ~150ms (Candle) per chunk. A 1 MB document
chunked into 256-token windows is ~60 chunks → 4–9 seconds. This is not acceptable for a pre-tool hook
that must answer in milliseconds.

### The solution: selective inference

The structural tier already identifies regions of interest:

1. **Segments with structural observations** — the ML tier corroborates or challenges these.
2. **Segments the DocumentMap register flags as anomalous** — the ML tier classifies these.
3. **Segments in concealing contexts (HTML comments)** — already flagged; ML adds confidence.
4. **Decoded content that tripped a rule** — ML confirms the decoded payload.

Only these segments are sent to the model. A clean document with no structural signals and no register
anomalies skips the ML tier entirely. The default path's latency is unchanged.

### Measured latency (T005)

**Machine**: as R1 — i9-12900HK, Linux (WSL2), `--release`, `candle-cpu-f32`. Candle reports 4 threads.
Each figure is the median of ten warm runs of a single short input (13–22 tokens), measured by
`please-eval model smoke --runs 10`. Load time is a cold `VarBuilder::from_mmaped_safetensors` plus
tokenizer construction.

| model | params | load | median inference | tokens |
|---|---|---:|---:|---:|
| `protectai-deberta-v3-small` | 142M | 795 ms | **183.3 ms** | 13 |
| `prompt-guard-2-86m` | 86M | 2298 ms | **443.9 ms** | 16 |
| `all-minilm-l6-v2` | 22M | 52 ms | **34.2 ms** | 11 |

Two of these contradict the estimates they replace.

**Candle is slower than the ~50–150 ms this section assumed** — 183 ms for the small classifier, 444 ms
for Prompt Guard. The `parry-guard` figures that estimate came from are Apple Silicon; this is x86 under
WSL2, and the gap is large enough that the ONNX backend (R1: ~5–6× faster) stops being a nicety.

**Prompt Guard 2 86M is the slowest model despite having the fewest parameters.** Its 2.3 s load and
444 ms inference are dominated by its vocabulary: a 16 MB `tokenizer.json` against ProtectAI's 8.7 MB,
and an embedding matrix large enough to make an 86M-parameter model a 1.08 GiB download. Parameter count
is the wrong proxy for cost here, and SC-608's multilingual measurement will pay this on every row.

Revised scenario table, computed from the per-chunk medians above rather than estimated:

| Scenario | Chunks sent to ML | ProtectAI | Prompt Guard | MiniLM |
|---|---|---:|---:|---:|
| Clean document, no signals | 0 | 0 ms | 0 ms | 0 ms |
| Document with 1–3 structural findings | 1–3 | 183–550 ms | 444–1332 ms | 34–103 ms |
| Document with register anomalies | 2–5 | 367–917 ms | 888–2219 ms | 68–171 ms |
| Full scan (`--ml-full`), 1 MB / ~60 chunks | 60 | ~11 s | ~27 s | ~2 s |

The selective approach keeps the common case fast and pays the ML cost only where it changes the answer
— and on these numbers it is not an optimisation but the only thing that makes the tier usable at all.
FR-652 making selective inference the default is load-bearing, not a preference.

One number the outlier experiment already depends on: R3 estimated MiniLM at "~15 ms per segment". It is
**34 ms**. At the measured mean sibling group of 7.4 segments, the embedding pass alone is ~253 ms per
document before any classifier runs.
