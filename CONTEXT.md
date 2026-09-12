# PLEASE

PLEASE detects prompt-injection attempts in text reaching an AI agent and evaluates detection against named corpus slices. This glossary records domain terms used in the architecture discussions.

## Language

**Evaluation run**:
A named evaluation with a fixed selection of intended slices, saved results, and the pipeline configuration that produced them. The intended slices are declared before scanning; a different selection requires a new run name.
_Avoid_: Experiment (also used for separate model-feasibility work)

**Slice**:
A named collection of evaluation rows defined by a corpus query or a local corpus reader, with its own reporting and gate eligibility.
_Avoid_: Dataset (a slice may cover only part of a dataset)

**Incomplete evaluation run**:
An evaluation run whose intended results are not all available and valid, including a run interrupted before completion or containing corrupt saved results.
_Avoid_: Clean run (absence of usable results is not successful evaluation)

**Partial report**:
A report showing the available valid results of an incomplete evaluation run and explicitly identifying its incompleteness.
_Avoid_: Successful evaluation (producing a report does not mean the gate passed)

**Unverified evaluation run**:
An evaluation run whose saved records cannot establish completeness, including older runs without a declared selection of intended slices. It cannot pass the gate and requires a rerun.
_Avoid_: Complete legacy run (existing result files do not prove that all intended results were saved)

**Gate**:
The evaluation check that applies baseline and criterion rules and returns a pass or failure; completeness must be established before a run can pass. Incomplete and unverified evaluation runs fail it.
_Avoid_: Report (a report presents results without establishing a pass)

**Judge response envelope**:
The provider's response containing completion metadata and content blocks, including the requested classification tool call.
_Avoid_: Judge report (the bound report is constructed after response validation)

**Judge response acceptance**:
The checks establishing that a judge response envelope is complete and unambiguous before its tool input is interpreted against a captured request.
_Avoid_: Judgement (acceptance checks do not determine what a finding means)

**Rule-set acquisition**:
Reading caller-supplied rule files in order, parsing each with its file attribution, and asking core
preparation to build the built-in base plus those additions and disabled rule IDs. Acquisition returns
one complete engine or an attributed error; it never continues with only the files that loaded.
_Avoid_: Rule preparation (core's separate, filesystem-free validation and construction step)

**Frame eligibility**:
Whether a raw rule match satisfies its declared anchor in the bytes being searched. A frame-anchored
match is eligible only when its start is a semantic-unit boundary according to the shared structure
predicate. Ineligible matches enter neither findings nor suppressions.
_Avoid_: Quoting suppression (a separate decision applied to an already eligible finding)

**Frame-aware matching**:
Matching that enforces frame eligibility within the searched buffer before returning rule matches.
Direct and decoded buffers use their own coordinates; decoded evidence is attributed to its original
encoded region only after matching.
_Avoid_: Context review (the optional judge's interpretation is a separate operation)

## Agreed behavior

Agreed during the architecture discussion on 2026-09-11 and implemented by the evaluation run module in `crates/eval/src/run.rs`:

- An incomplete evaluation run may produce a clearly marked partial report.
- Its gate must fail even when every available slice meets its baseline.
- A run declares its intended slices before scanning; that selection remains fixed.
- Adding slices requires a new run name.
- A run must prove completeness before its gate can pass; inability to prove it is a failure requiring a rerun.
- Older saved runs without evidence of their intended selection are unverified and require a rerun; their existence does not grant a compatibility exception to the gate.

The current implementation restarts interrupted evaluations under a fresh run name; automatic resume is not implemented. The module saves fixed slice definitions, publishes results atomically, and verifies row counts and checksums before the gate can pass.

Completeness here concerns the integrity of saved evaluation results for the supplied input rows; input-corpus verification and detector coverage gaps within saved rows remain separate concerns.
