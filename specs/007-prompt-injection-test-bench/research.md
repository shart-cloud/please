# Feature 007 research decisions

This note closes plan Phase 0. Measurements are instrument evidence, not detector-accuracy claims.

## R1 — Threat and trust boundary

Candidate bytes, case metadata, and adapter output are hostile data. They never become command-line
arguments, paths, environment variables, policy, permissions, labels, or shell input. Ground truth travels
from the verified pack directly to saved results and is absent from the JSONL request type.

Adapters are caller-selected code, not sandboxed malware. On Linux/WSL the runner mechanically provides a
fresh run-owned working directory, clears the environment, uses an absolute executable without a shell,
starts a new process group, kills that group on failure, bounds request/stdout/stderr bytes, and enforces
startup and per-case deadlines. Asset opens use `O_NOFOLLOW`, then verify regular-file status, length, and
digest. A parent credential-canary integration test proves undeclared environment does not cross the child
boundary.

Offline mode rejects adapters declaring network capability. Feature 007 does not create a network namespace,
seccomp policy, container, or filesystem sandbox; a dishonest or compromised executable can still use host
capabilities. That remains an explicit trust assumption until a separate sandbox design can provide portable,
tested guarantees.

## R2 — External adapter lifecycle

The universal boundary is a long-lived, sequential JSONL process protocol, version
`please-bench-jsonl/v1`. The host sends one identity-bound handshake, then one request at a time. The adapter
must produce exactly one strict response carrying the host-issued opaque request id. Candidate bytes use hex
encoding so arbitrary bytes and newlines cannot forge frames.

Protocol corruption, wrong ids, duplicate responses, oversized output, stderr floods, EOF, successful exit
without a response, crashes, and hangs are separate observable failures. A corrupt or timed-out process group
is terminated and may restart only within the experiment's fixed budget. Completed stochastic responses are
never silently retried.

## R3 — Identity and layout

SHA-256 identities are domain-separated and length-framed. Pack, case, system, experiment, request, row,
native output, and complete results have distinct domains. Ordered case digests, system digests, normalizer
versions, limits, repetitions, and execution mode determine semantic run identity. Host metadata and elapsed
time are recorded but excluded from semantic identity, allowing meaningful replay comparison across hosts.

A run directory is created once and contains `run.json`, `results.jsonl`, and run-owned `work/`. The initial
manifest says `incomplete`; `complete` plus the result byte count, row count, and digest is published only
after a flushed and synchronized JSONL result file exists.

## R4 — Pack and exposure handling

Version-1 packs contain a strict JSON manifest, strict versioned taxonomy, and an exact `assets/` inventory.
Validation rejects unknown fields, traversal, symlinks, special files, missing/extra/changed assets, duplicate
ids, conflicting artifact labels, unknown taxonomy values, unsorted tags, surface/context mismatches, and
exact, normalized, or family leakage across splits.

Holdout verification requires exposure JSONL. Exact input digests, NFKC/case/whitespace-normalized digests,
and declared families are all exclusion keys. `bench exposure` emits one new record per case from a verified
complete run without copying prompt text. Existing feature-006 runs retain their historical format; they are
not reinterpreted with missing identities filled from current defaults.

## R5 — Initial systems and normalization

| System | Surface | Native output | Identity and operating point | Status |
|---|---|---|---|---|
| PLEASE structural mechanism | Artifact | Findings and threshold decision | Feature-006 engine/rule-set/policy identity; low historical floor | Implemented in process |
| PLEASE shipping configuration | Artifact | Findings and shipping decision | Expressible as a separate system manifest; optional ML/judge identities remain feature-gated | Supported by adapter contract |
| Contextual reference fixture | Artifact + contextual | Native label, optional confidence, evidence, diagnostics, cost | Executable SHA-256, adapter version, fixed label vocabulary | Implemented for protocol/pilot testing only |

Normalizers are one-per-surface, versioned, and identity-bound. PLEASE impact scores are not called
probabilities. External confidence remains native. Context-free artifact results are never promoted to a
contextual relation. A real third-party paper implementation remains a manual integration choice because no
unverified download, license assumption, or model identity belongs in normal CI.

## R6 — Bounds and scale

The committed scale probe generated one shared benign asset with distinct first-party case records and ran
the in-process adapter with `max_in_flight=1`. Measurements on the WSL development host:

| Cases | Pack verification | Run | Report reconstruction | Observed in flight |
|---:|---:|---:|---:|---:|
| 1,000 | 69 ms | 471 ms | 135 ms | 1 |
| 10,000 | 695 ms | 4,203 ms | 1,278 ms | 1 |
| 75,000 | 6,350 ms | 40,496 ms | 13,707 ms | 1 |

The compact 10,000-case manifest measured 5,220,455 bytes; extrapolation and the 75,000-case run justified a
64 MiB manifest ceiling. Candidate input remains independently capped at 16 MiB maximum, with the example
experiment using 1 MiB. Request, stdout, stderr, startup, per-case, restart, repetition, and in-flight limits
are explicit experiment fields rather than hidden adapter choices.
