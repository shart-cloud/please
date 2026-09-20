# Laya offline development screen

Human-directed, Codex-authored evaluator-only experiment. No shipping integration,
training, calibration fitting, release authority or new Jev requests.

The frozen sample contains 1,200 public rows (600 attacks / 600 benign, one fifth
of each September 18 source/truth quota) and all 600 contextual rows. Selection
uses a fixed case-ID hash, not outcomes. Contextual rows are correlated within
150 groups and 15 families; labels are same-author, not independently reviewed.

Two pinned checkpoints run locally: English Laya and typed-decisions. Both are
tested with original Jev questions/state and a separately frozen compact recipe.
The matched-question arm was added after token-only admission and before corpus
inference. Candidate-only, context-only and reversed-option controls each use
60 contextual rows, one four-context group per family. Planned final rows: 7,560.

Laya accepts a native choice only at max probability >=0.7 and margin >=0.15,
otherwise indeterminate. Entropy confidence is recorded but is not correctness
probability and is not gated. Historical Jev gates are preserved. No threshold
search is performed. Public improvement requires higher attack recall with no
extra benign false alarms; contextual improvement also protects conflict and
unknown recall and false-conflict count. These are descriptive screen criteria,
not independent calibration or promotion gates.

The adapter verifies immutable source/asset identities, native request bytes,
frozen historical context mapping and model-state candidate equality. All
instructions, option text and serialized state must fit the exact upstream
token packing without shortening; reserved markers are refused. An admitted
sequence is compared token-for-token with the official builder. Errors and
input-cap abstentions remain in denominators.

Models use the existing decision-poc Python environment, four CPU threads and
the official CUDA autocast path on the local RTX 3050 Ti Laptop GPU. Recorded
package versions and effective model temperatures remain in cache. Each native
run loads one persistent model and performs one synthetic warmup. Offline flags
and local assets prevent ordinary Hub downloads during inference; this is not
an OS network sandbox. Device fallback is rejected. Cold startup, synchronized
forward-call time and whole-decision timing are separate. Hardware contention
is uncontrolled.

## Evidence and reproduction

Instance: .cache/laya-experiment-20260919/. Never rerun setup over old outputs.

- recipes.json and selection.json were hash-frozen before inference.
- fetch.py downloads pinned source/model files; no benchmark content is uploaded.
- prepare.py seals native packs and initial runtime identity.
- preflight.py checks token admission and synthetic reference parity.
- The original execution freeze is retained, along with the matched-question
  amendment (v2) and protocol-only correction (v3).
- adapter-v3.py is the final frozen cache snapshot; pass2 manifests select it.
- run.py runs the pass2 manifests sequentially; each saved run is verified.
- report.py joins preserved Jev captures by case/input/request identity.
- tests use no weights or network.

Run unit checks:

    python3 -m unittest discover -s crates/eval/scripts/decision_laya -v

Run reporting on completed evidence:

    python3 crates/eval/scripts/decision_laya/report.py

For a new experiment, provision a new output root and update the explicit paths
and freeze generation together. The scripts intentionally refuse run overwrite.
The pass2 manifest generation is recorded in execution-freeze-v3.json and the
immutable manifests; do not regenerate them into the existing output location.

## Retained protocol failure

The first adapter mistakenly required trusted_context even when the host omitted
that optional field for public rows. Those public rows never reached inference.
An interrupted contextual run and all earlier logs remain preserved. A regression
test now covers field omission. The correction changes no cases, prompts, gates
or model behavior. Unexpected adapter errors stop the orchestrator before another
run; allowed input limits remain explicit abstentions.

## Completed run index

All 14 final runs completed and verified: 7,560 reported local rows, zero new Jev
requests. run-index.json identifies the exact selected directories. After the
initial run.py startup interruption, continue_runs.py completed the remaining
arms and retained same-limit retries. Three zero-response startup failures are
preserved separately from the final model-quality rows. Cold initialization is
included in the native host's first request-acceptance timer, despite its separate
startup allowance; this operational limitation is not a corpus model verdict.

finalize.py verifies row counts, frozen hashes and zero reported remote requests;
report.py writes source-stratified Markdown/JSON and render.py produces the HTML.
The last two scripts may regenerate aggregate reports from existing evidence;
never rerun provisioning or native run creation over the original paths.
