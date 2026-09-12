# Input acquisition and classifier window repairs — 2026-09-11

This is the first implementation slice from the architecture review. It repairs input acquisition
and per-window classifier preprocessing. The remaining architectural findings are still open.

## Input acquisition

The CLI reads at most `max_input_bytes + 1` bytes from each file or stdin. Observing the extra byte
produces an `input_size` coverage gap immediately, without waiting for EOF or invoking detectors,
ML, or the judge. Size validation precedes text validation because a bounded prefix may split UTF-8.
Core still checks the size of complete byte buffers supplied by library callers.

For a stopped read, `target.bytes` is the observed byte count and `target.bytes_is_lower_bound` is
`true`. Complete reads retain the existing JSON shape; absent means false. The gap detail says
“at least” rather than claiming an exact length. No digest of a partial input is recorded.
Rust callers constructing `TargetRef` directly must supply the new boolean; its constructors
default to false.

A byte cap does not impose a deadline on a source that stalls before sending enough bytes to
exceed the cap. Directory enumeration and rule-file acquisition are separate resource boundaries.

## Classifier preprocessing

The classifier encodes payload tokens without added special tokens, reserves the postprocessor's
declared special-token budget, and splits payload windows. It then applies the tokenizer's
postprocessor independently to every window before building tensors. Windows that cannot fit
payload plus special tokens fail explicitly. Token offsets continue to refer to the original text.

This repair preserves zero overlap and maximum-score pooling. Per-window scores and spans are not
yet exposed in `MlReport`; overlap selection, chunk-level reporting, and full inference identity
remain follow-up work. Previous model accuracy measurements describe the old preprocessing and
must not be presented as measurements of this corrected implementation.

The regression suite covers an open oversized stdin pipe, file/stdin length boundaries, zero caps,
split UTF-8, per-window special tokens, boundary-adjacent payload tokens, and short-input parity.
A tokenizer-only differential test compares the production window helper with the tokenizer's
native overflow preprocessing, without loading weights:

```sh
PLEASE_TEST_TOKENIZER=/path/to/tokenizer.json cargo test -p please-ml --lib \
  cached_tokenizer_matches_native_overflow_preprocessing -- --ignored
```
