# Feature 007 data model

## Identity graph

```text
Taxonomy bytes ─┐
Asset digests ──┼─> CasePack digest ─┐
Case labels ────┘                    │
                                     ├─> Run identity ─> request id ─> row id
System manifest ─> System digest ────┤
Experiment limits/schedule ──────────┘
```

All identities use SHA-256 with a domain name, a zero separator, and a length-prefixed canonical JSON
payload. Timing and host telemetry do not alter semantic run identity.

## CasePack

`pack.json` records schema, stable id/version, declared digest, creation and license provenance, purpose,
taxonomy file identity, and an ordered case list. `taxonomy.json` separately governs technique and delivery
vector vocabularies. Every referenced candidate is a regular file under `assets/`; the inventory must contain
no unreferenced files.

Case-pack schema v2 also records optional contextual-group baselines. A baseline must identify a contextual
case in that exact group; groups without one are compared using all ordered pairs.

A `BenchCase` binds exact bytes and length to source, caller-established provenance, ground truth, label
provenance/disagreement, group, family, split, delivery vector, techniques, and presentation. Artifact cases
carry `injection`, `benign`, or `ambiguous`. Contextual cases carry a trusted task, typed permissions, and one
of `aligned_instruction`, `conflicting_instruction`, `non_instruction`, or `indeterminate`.

## SystemUnderTest

A strict system manifest binds stable id/version, adapter version, configuration identity, capabilities,
trusted-context requirement, determinism claim, review authority, operating point, model/prompt/rule/runtime
identities, adapter configuration, and one independently versioned normalizer per supported surface.

The in-process PLEASE adapter records effective policy, engine version, rule-set digest, and requested tiers.
The subprocess adapter additionally binds the exact executable SHA-256, arguments, explicit environment,
and network capability.

## Experiment and RunPlan

An experiment references one pack, one or more systems, exposure histories, repetitions, offline/network
mode, and every resource/scheduling bound. Validation resolves and verifies all identities before creating an
output directory. The immutable run plan records ordered case digests, prepared runtime identities, host
metadata, and an initially incomplete completion record.

`max_restarts` counts replacement child starts after the initial start and is capped at 100. Input, request,
stdout, stderr, startup, per-case, and in-flight limits remain independent.

## Adapter protocol

The host handshake binds protocol, system id, and system digest. A case request contains only request id,
surface, encoded candidate bytes and identity, caller provenance, and—only for the contextual surface—the
trusted context. It never contains ground truth, label provenance, normalizer mapping, operating threshold, or
runner limits.

An adapter response contains request id and a native response: label, optional confidence, bounded evidence,
diagnostics, abstention, remote-request count, and declared cost. Strict envelopes reject unknown fields.

## BenchResult

Each append-only row keeps these categories separate:

- Ground truth and strata copied from the verified pack.
- Case, input, normalized-input, system, normalizer, request, row, pack, and run identities.
- Coverage: completed, unsupported, abstained, timeout, crashed, invalid output, or unavailable.
- Raw native response and exact bounded stdout/stderr bytes encoded as hex with independent digests.
- Surface-specific normalized decision.
- Elapsed time, output volume, optional peak memory, remote requests, and declared cost.

Reports stream verified rows. Binary artifact denominators exclude ambiguous labels and unsupported
capabilities. Requested-system failures on positives count as non-detections and as their failure category;
failed negative rows receive no true-negative credit. Contextual output uses the full four-way matrix. Every
report is cut by surface, source, delivery vector, technique, and system, then shows paired group transitions.

## ExposureRecord

Exposure JSONL stores no candidate text. One row binds a prior pack and case to exact input digest,
normalized digest, family, use kind, and recording time. Any match prevents a later case from being described
as untouched holdout material.
