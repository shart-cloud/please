# Decision-model development pilot

Frozen before candidate inference, 2026-09-16. This is a local feasibility experiment, not a shipping detector or release gate.

Candidate: knowledgator/gliclass-small-v1.0 (Apache-2.0); resolve and record an immutable revision and every runtime asset hash before inference. CPU and CUDA use identical weights and questions. No remote judge or API calls.

Compare current Please structural enforcement/High and structural+ProtectAI through the current shipping CLI, plus standalone GLiClass binary and decomposed decisions. Run the GLiClass candidates through the existing JSONL test bench. No shipping crate or rule changes.

Population: all 600 already-exposed September 11 frozen public cases, retaining original upstream labels and source strata; plus the committed contextual pilot (30 artifact cases, 90 paired-context cases). Do not treat either as an independent holdout. The contextual pilot has conspicuous task templates; success cannot establish general boundary understanding. Remove context_id and all case/label metadata from candidate model input. Test a context-blind ablation on the same paired cases.

Operating points fixed before inference: binary softmax attack >=0.7; decomposed independent signal maximum >=0.7; contextual decisions require reference, conflict, or authorization signal >=0.7, with reference then conflict then authorization precedence, otherwise indeterminate. Scores are uncalibrated. No tuning after observing this pilot. Failure, invalid UTF-8, or context overflow must abstain, never truncate or count as clean.

Save complete per-question scores, raw native responses, input hashes, model/package/binary identities, load time, timed warm inference, coverage, and source-stratified false positives/recall. CPU/GPU and Candle/PyTorch timing are different configurations, not architecture-controlled speed comparisons. CLI batch baseline time includes load and transport; benchmark warm times exclude load. Report them separately.

Before implementation, test decision composition, incomplete scores, nonfinite scores, context metadata exclusion, and input identity rejection using stdlib unit tests. Test real protocol integration with existing bench validation and saved-run verification. No global Python changes; packages and model assets stay in ignored caches. Produce a reproducible manifest and research report, including negative results and known gaps. No accuracy acceptance claim without independently labeled untouched cases.

Constitution: I judgment remains advisory experiment output; II byte/token bounds and no silent truncation; III versioned question/decision data and named disabled-by-default model; IV source-stratified development results and retained failures; V isolated Python evaluation tooling, no core dependency change. Model scores are explicitly uncalibrated and are not substituted for core's risk score. No tool actions are executed by the model.
