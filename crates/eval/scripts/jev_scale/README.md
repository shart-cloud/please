# Larger Jev development evaluation

This isolated evaluator continues the September 16–17 work without changing the
shipping CLI, prompts or thresholds. It uses 6,000 source-stratified public cases
and a separate 600-row shipping-context regression. The public recipe is the
previous three-choice artifact classifier, **not** the CLI's four-way relation
question. Contextual requests execute the captured installed `plz clap` binary;
preparation also verifies byte-identical `plz jev --request-only` output.

The public inputs are verified against the existing committed corpus manifests
at the pinned Necent revision. Labels and exact bytes must match. Sampling uses
ascending content hashes within predeclared source/label quotas, rejects
normalized duplicates and conflicting labels, and never inspects predictions.
The inventory records oversized and serialization-source exclusions. All raw
third-party text stays in ignored cache. These are exposed development inputs;
no independent holdout or permission labels are claimed for public data.

The contextual partition was previously prepared for conditional research-H
confirmation. Here it is only a shipping-recipe regression. The H screen did not
pass, H is not run, and this does not satisfy its confirmation or promotion gates.

From the repository root:

```bash
python3 -B -m unittest discover -s crates/eval/scripts/jev_scale -v
python3 -B crates/eval/scripts/jev_scale/scale.py prepare --out .cache/jev-scale-NEW
python3 -B .cache/jev-scale-NEW/code/scale.py baseline --out .cache/jev-scale-NEW
python3 -B -u .cache/jev-scale-NEW/code/scale.py live --out .cache/jev-scale-NEW
python3 -B .cache/jev-scale-NEW/code/scale.py replay --out .cache/jev-scale-NEW
python3 -B crates/eval/scripts/jev_scale/report.py --out .cache/jev-scale-NEW \
  --publish docs/research/jev-scale-NEW
```

`live` is the only network step. It reads `TYPESAFE_API_KEY` or uses a hidden
terminal prompt; the key is memory-only and never enters a command argument,
manifest or saved capture. One sequential pass permits at most 6,600 attempts,
two hours, no retries, a 35-second outer deadline, and circuit breaking after an
authentication/422 response, three consecutive failures or 30 total failures.
Provider pricing is unknown. The frozen code and requests are verified before
running. Existing runs cannot be overwritten or restarted.

Public provider responses, including parse-rejected replies, are retained unless
they reflect the credential. Contextual captures retain the real CLI advice;
the shipping CLI does not expose rejected raw provider bodies. Interrupted or
early-stopped runs remain incomplete and cannot produce a complete native replay.
The report checks every saved capture against frozen request identities; for
complete runs it also checks native replay and the structural baseline. Replay
makes zero API calls and its duration is not remote latency.

Reports include per-source recall/false positives, acceptance and abstention,
harmful-label and language strata, contextual confusion matrices, delivery and
workflow breakdowns, failures, usage and latency. Their union detector is an
offline analysis only. No threshold calibration or release-authority change is
performed. Inputs, code, binaries, requests, failed responses and old attempts
are preserved for review.
