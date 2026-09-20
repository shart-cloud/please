# Jev usage-pattern experiment

This is a benchmark-only follow-up to jev_followup. It does not change the installed CLI.

- Read docs/research/jev-usage-plan-2026-09-16.md for the frozen variants, budget, gates and limitations.
- Run `python3 -m unittest -v` in this directory.
- `python3 prepare.py` requires a new output directory; it checks the previous frozen synthetic audit and freezes all requests before inference.
- Run the frozen `code/run.py`. Enter a temporary key through its hidden prompt. The key is never a command argument or a file.
- `python3 report.py` verifies frozen hashes, recomputes every captured prediction, checks shared C/P response identity, verifies native replay, scans saved outputs for credentials and publishes the report.
- No automatic retry or post-outcome prompt/threshold change. The 600-case confirmation occurs only for a recipe passing every predeclared screening gate.
- P shares C captures and costs no extra screen requests. H/X use caller-supplied workflow mode, so report them separately from model-only changes.
- `api_worker.py`, `capture_adapter.py`, `legacy_common.py` and `previous_contracts.py` retain the prior transport, native replay and strict response contracts. Reporting code does not alter frozen inference code.
- Native replay remote-request counts are zero; real API counts and latency are in captures/summary. Delivery copies are correlated and labels are same-author development labels.
