# Jev comparison with the existing Please benchmarks

This isolated evaluator runs a single bounded, explicitly network-enabled pass through the same 1,950 exposed cases: Phase 2 development (480), calibration (240), shuffled context (480), challenge (30), and the earlier pilot/public suite (720). Source text stays in ignored cache; reports contain aggregate metrics and identifiers.

The contextual surface invokes a captured build of the real `plz clap` command. A deterministic mapping preserves task text and each literal resource/action/decision entry as a tool-action boundary. It explicitly leaves unlisted permissions unspecified and sends no case identifiers or expected labels. The three delivery types are mapped to caller-owned CLI provenance.

Artifact detection uses a separate frozen three-choice API request. It does not pretend the shipping contextual command produces artifact labels. Both use support >=0.7, margin >=0.15 and provider confidence >=0.5. Native Choice probabilities and returned model identifiers are retained. These are not calibrated Please probabilities.

## Run and verify

From the repository root:

```bash
python3 -m unittest discover -s crates/eval/scripts/decision_jev -v
python3 crates/eval/scripts/decision_jev/prepare.py
python3 -u .cache/decision-jev-20260916/code/run.py
python3 crates/eval/scripts/decision_jev/report.py
```

Preparation refuses an existing output directory. Use a new named output for a new experiment; never overwrite saved runs. It copies the exact existing packs and captures the CLI, adapter, broker code, recipe and hashes before inference. The first preparation attempt is preserved separately; its absolute pack paths were refused by the native experiment checker before any dataset requests.

The runner prompts without echo, holds the credential only in memory, and passes it to CLI child environments. A private Unix socket bridges the native runner's cleared environment; no credential enters native manifests or persisted command arguments. All requests go to the fixed TypeSafe endpoint with redirects refused. The bounded session allows one request per row, no automatic retries, a 30-second API timeout, 1-hour session cap, and circuit breaking on authentication/schema or repeated errors. The corrected run reserves 1,999 requests; with the retained first smoke request, total allowance stays at 2,000. Provider cost is unknown; native declared zero means unpriced, not free.

Before transmission, all 1,350 synthetic cases were checked against their fixture generators or first-party pilot, and all 600 public cases against the pinned Necent dataset freeze. The simulated repository_file/tool_response labels do not refer to actual private files or live tool outputs. The audit is retained in export-provenance-audit.json.

## Interpretation

Development, calibration and prior public cases are exposed. No independent labels or holdout are claimed. The existing 120 disputed shuffled mappings remain excluded from scored shuffled metrics. Local-model-specific special-marker and 512-token cases are not treated as cross-model semantic labels; they stay in the native run with their original labels.

Reports show contextual macro recall, full-group correctness, false reassurance, missing-context errors, per-delivery and workflow counts, family bootstrap intervals, all calibration points, attack recall and benign false positives by public source, failures, token usage and remote latency. Local warm inference and single-pass remote end-to-end latency are different measurements. No shipping thresholds or authority change follows this comparison automatically.

Jev-specific one-sided ablations and repeated API trials are outside this bounded pass. Their control-gain and repeatability gates remain unmeasured. Optional diagnose.py makes up to five fresh post-outcome requests within the original 2,000-request ceiling; diagnostics never replace the frozen benchmark rows.
