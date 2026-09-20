# GLiNER2 contextual regression through PLEASE — September 18, 2026

All 600 cases completed through the native PLEASE benchmark, using the validated Rust/Candle
classification adapter. Saved-result integrity verification passed. There were no input/runtime
errors or API calls; 231 predictions were indeterminate and 369 were determinate.

| Expected relation | Candle GLiNER2 correct | Jev shipping recipe correct |
|---|---:|---:|
| Authorized instruction | 9/150 (6.0%) | 149/150 (99.3%) |
| Conflicting instruction | 108/150 (72.0%) | 138/150 (92.0%) |
| Material to analyze or quote | 36/150 (24.0%) | 1/150 (0.7%) |
| Missing-context indeterminate | 60/150 (40.0%) | 108/150 (72.0%) |

The Candle implementation matches the tested reference behavior; that does not make the model
accurate at caller-authority judgments. It labeled 96 authorized cases as conflicting and
abstained on another 45. It labeled 3 conflicting cases as authorized. These results do not
justify promotion into shipping decisions.

The cases reuse 50 candidate texts across 150 correlated groups and 15 workflow families.
Labels are same-author development labels, with independent review pending. Different models
use different recipes and score gates. The 6,000-case public GLiNER2 run is separate; check
`.cache/framework-models-20260918/completion.json` for its completion and combined report status.

Open this actual framework run without inference:

```bash
.cache/framework-models-20260918/please-eval bench view \
  --run .cache/framework-models-20260918/run-contextual
```

A standalone HTML view is at `.cache/framework-models-20260918/run-contextual/report.html`.
The framework's overall contextual correctness measure counts determinate matches; the table
above separately reports valid missing-context abstentions, excluding provider/input failures.

See [implementation validation](gliner2-candle-validation-2026-09-18.md) and
[the full Jev report](jev-scale-2026-09-18.md) for identities, limits and source-stratified results.
