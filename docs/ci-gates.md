# Regression, release quality, and real inference

The September 11 checkpoint is `cc5ba34`. It contains the source/export policies, replay experiments,
verdict-composition repairs, and destination-grant correction. CI now distinguishes three questions.

## Does a change preserve tested behavior?

The regular CI workflow runs tests and Clippy in three configurations: the workspace defaults
(including judge), the CLI with `--no-default-features`, and `please-ml --features candle`.
The Candle configuration compiles real inference code but leaves the eight expensive real-weight
tests explicitly ignored. It does not download models or claim that inference ran.

When reproducing the matrix locally, run configurations sequentially if they share `target/`:
both CLI configurations write `target/debug/plz`, which their integration tests execute.
GitHub's separate matrix jobs do not share that runtime path.

`tests/fixtures/detection-baseline.json` records all 71 existing labeled fixtures: input SHA-256,
original label, observed detection, and incomplete-coverage status. The comparison uses
`ScanPolicy::default()` and measures detection at the `Low` floor, as the original fixture tests did.
It does not change source policies, labels, thresholds, or detector behavior. The baseline records
43/51 positives detected and one false positive among 20 benign fixtures.

Every added, removed, relabeled, edited, newly detected, newly missed, or newly incomplete case fails
the comparison until reviewed. Improvements also require a baseline update so the next regression
cannot silently spend the recovered coverage. Review the individual case and evidence before editing
the corresponding row; never update the entire baseline just to make a failed run green.

Known false negatives remain labeled as injections:

- `indirect-email-001`, `indirect-email-007`, `indirect-email-008`, `indirect-email-009`
- `indirect-mcp-001`, `indirect-mcp-002`
- `indirect-repo-cursorrules-001`, `indirect-skill-002`

The known false positive remains labeled benign: `benign-tool-001`. Run with `--nocapture` to see
all case explanations, including in a passing regression run:

```bash
cargo test -p please-core --test fixtures --locked -- --nocapture
```

Regular CI also checks core isolation, the core dependency allow-list, the default CLI's ML isolation,
and the offline CLI's known HTTP/TLS dependency exclusions. The credential-leak check scans output
even when tests fail, then fails on either a test failure or a detected leak.
Live judge agreement/discrimination tests are explicitly ignored during normal runs, so canary
credentials do not accidentally start live evaluation. Request them separately with `--ignored`.

## Have the fixture release criteria been met?

The `Release quality` workflow runs manually or on `v*` tag pushes. It executes the two explicitly
ignored absolute-quality tests and retains the log as an artifact:

```bash
cargo test -p please-core --test fixtures --locked -- --ignored --nocapture
```

SC-002 still requires every positive to be detected. SC-003 requires at least 200 benign fixtures
and at most 1% false positives. Both checks currently fail. A green regression workflow does not
mean these criteria are satisfied; the stricter checks do not use the regression baseline.
This workflow reports a release check; it neither publishes releases nor configures repository
rules to prevent publishing after a failure. Corpus-scale evaluation remains a separate requirement.

## Did real inference run with the intended models?

The `ML inference` workflow runs manually or on `v*` tag pushes. It fetches only the two public
ProtectAI/MiniLM bundles at the revisions pinned in `crates/eval/corpus/models.toml`, using the
existing acquisition code and a pinned Hugging Face CLI. A cache hit still undergoes asset-size
and SHA-256 checks. It then runs all eight real-weight tests, serially, with Cargo/model offline
flags. Missing or corrupt assets fail the job; no model test can report success by skipping its body.
This proves the tested inference behavior, not general classifier accuracy or suitability for release.

With the dependencies and pinned assets already cached, the same gate runs locally:

```bash
bash ci/check-ml-inference.sh
```

`PLEASE_EVAL_CACHE` selects the cache root; otherwise the existing XDG/home convention applies.
The script never downloads assets. An explicit `--ignored` invocation of the real-weight tests also
fails on missing model/config/tokenizer files, while the script additionally verifies every pinned
runtime asset before loading anything.

Workflow triggers and failure handling follow the [GitHub Actions workflow syntax](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax).
