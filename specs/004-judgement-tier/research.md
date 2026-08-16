# Phase 0 Research: the judgement tier

**Feature**: `004-judgement-tier` | **Date**: 2026-08-16

Architecture decisions live in [plan.md](./plan.md) as D1–D8 and are not repeated. This document records the
things that had to be **measured or looked up** rather than reasoned about, in the format the earlier features
used: decision, rationale, alternatives.

Two of the four were already decided by the examiner and are recorded here with the evidence that was owed
(D2 promised a dependency measurement before the crate was added; D3's ordering was confirmed against a live
environment). The other two were open.

---

## R1 — `ureq`, measured: 22 crates against `reqwest`'s 87, and no executor

**Decision**: `ureq 3` with `default-features = false`, features `rustls` and `json`.

**Measured**, in a scratch crate, resolving each candidate alone:

| Dependency specification | Crates | `tokio` |
|---|---|---|
| `ureq` — `rustls` only, no defaults | **22** | no |
| `ureq` — defaults | 27 | no |
| `reqwest` — `blocking`, `json`, `rustls-tls`, no defaults | **87** | **yes** |

With `serde`, `serde_json` and `ureq`'s `json` feature — the realistic judge configuration — the total is
**32 crates, of which 4 are already in `please-core`'s graph** (`base64`, `cfg-if`, `memchr`, `serde_core`).
So the judge adds **28 crates** that are new to this repository.

### Re-measured at T004, against the resolver rather than the scratch crate

The estimate above was owed a check before the allow-list was built on it, because a stale baseline is a
gate asserting the wrong thing. Measured against the real `crates/judge` after `cargo add`:

| | |
|---|---|
| `ureq` resolved | **3.4.0** — feature names `rustls` and `json` are current; `rustls` implies `_ring` |
| `ureq` subtree | **23 crates** including itself (estimate: 22 — version drift, not a surprise) |
| `please-judge` total | **56 crates** |
| **New to this repository** | **19** (estimate: 28) |
| `tokio` | **0**, as promised |

The nineteen: `bytes`, `getrandom`, `http`, `httparse`, `libc`, `log`, `once_cell`, `percent-encoding`,
`ring`, `rustls`, `rustls-pki-types`, `rustls-webpki`, `subtle`, `untrusted`, `ureq`, `ureq-proto`,
`utf8-zero`, `webpki-roots`, `zeroize`.

Nine fewer than estimated, because the scratch crate resolved `ureq` alone while the real one shares more of
`please-core`'s graph than the four crates the estimate credited. **The direction of the error is the
comfortable one** and the conclusion is unchanged.

**One thing the measurement surfaced that the estimate did not**: `rustls` selects `ring` as its provider,
not `aws-lc-rs`. `ring` carries C and assembly and wants a working `cc` on any target without a prebuilt
artifact. That is a *build* dependency of the optional tier and reaches neither `please-core` nor the
default `plz` binary — but it is the reason `--features judge` may fail to build somewhere the default
build succeeds, and an operator hitting that deserves to find the cause written down rather than inferred
from a linker error.

**FR-419's guard asserts against 19, not 28.** `ci/cli-dependency-allowlist.txt` pins the default CLI graph
by exact name, so the count is documentation and the names are the contract.

**Rationale**: the numbers say what the argument said. `reqwest` is ~4× the tree and brings a tokio runtime
for a single synchronous `POST`, which is the objection that ruled out `rig.rs` one level down. Two further
points the measurement made concrete:

- **`ureq`'s whole tree is smaller than `please-core`'s own shipping graph** (22 against 27). The HTTP client
  for the optional tier weighs less than the engine everything else depends on, which is a proportion worth
  keeping.
- **`tokio: 0`.** Not "we avoid using async" but "no executor is present to be pulled in later by accident".
  `reqwest`'s blocking mode still resolves tokio, so the constraint would have been a convention rather than
  a fact.

**Alternatives considered**: `reqwest` — rejected on the above, and would be the right answer if streaming or
async batching were ever wanted; neither is (plan D2, spec Out of scope). Hand-rolled HTTP over `std::net` —
rejected: TLS is not a thing to hand-roll, and `please-core`'s isolation gate would not care either way since
this is a different crate. `rig.rs` — rejected by the examiner as too heavy for one endpoint, which the
measurement supports.

**Consequence for FR-419**: the CLI allow-list guard asserts *against* those crates by name — the default
`please-cli` build must contain **none** of them, and the `--features judge` build must contain them. The
second half matters as much as the first: a gate that only checks for absence passes trivially when the
feature is broken.

---

## R2 — Structured output: a tool-use schema, not "reply in JSON"

**Decision**: obtain the closed-enum response through the Messages API's **tool-use** mechanism — declare one
tool whose input schema is the feature set, and require it — rather than by asking for JSON in the prompt and
parsing prose.

**Rationale**: three of the spec's requirements are much easier to hold this way.

- **FR-405** wants no free-text field anywhere. A JSON schema with `enum` constraints *is* that requirement,
  expressed where the model can see it, rather than a hope about formatting.
- **FR-409** wants a non-conforming response rejected rather than salvaged. A schema gives an unambiguous
  conformance test; prose parsing invites a lenient path, and a lenient parser on adversarial input is the
  thing this project exists to warn about.
- **FR-406** wants the prompt free of leading words. Moving the answer space into a schema shrinks the prompt
  to a neutral instruction plus the enveloped content, so there is less prose in which to accidentally name
  the interesting answer.

There is a security argument too, and it is the stronger one. A model talked into ignoring its instructions
can still only emit a value the schema permits. **The blast radius of a captured judge is bounded by the
enum**, not by our parser's strictness — which is what makes the SC-406 property test a statement about the
design rather than about the quality of our validation code.

**Alternatives considered**: prompted JSON with strict parsing — workable and the fallback if a proxy does not
support tool use, but the conformance boundary moves into our code. Prefill / stop sequences — brittle across
providers. Free text plus a classifier — more moving parts than the thing being classified.

**Open**: an Anthropic-compatible proxy may not implement tool use. The client should detect a failure of that
shape and report it as `TierUnavailable` (FR-402) rather than silently falling back to prose parsing, because
a silent fallback would quietly relax the guarantee above.

---

## R3 — What a judged verdict must carry for attribution

**Decision**: record the resolved **model id**, the **prompt version**, and the **feature answers per span**.
Not the raw response, and never the credential.

**Rationale**: FR-416 asks for attribution and 001's SC-012 already established why — a digest whose job is
attribution has to outlive the thing that produced it. A model id serves the same purpose one level up: a
verdict judged by one model and one prompt is not evidence about another.

Prompt version is included because it changes the answers as surely as the model does, and it is the variable
*we* control. A prompt edit that shifts feature extraction with no record would be indistinguishable from a
model change, which is the debugging problem SC-407's agreement measurement exists to make tractable.

The feature answers are recorded because FR-407 computes the score from them: without them the score is an
unexplained number, and 002 spent its effort removing exactly those.

**Not recorded**: the raw response body. It is attacker-influenced text with no consumer, and storing it in a
verdict would create a channel for content to reach a reader that the sanitisation path never inspected.

**Alternatives considered**: hashing the response for reproducibility — attractive, but a hash of a
non-deterministic output is not comparable across runs, so it would record noise. Full request/response
logging — a debugging feature, and one that must never be on by default given FR-413.

---

## R4 — Where the judge sits in the scan pipeline

**Decision**: **after** finalization, as a transformation from `Verdict` to `Verdict`, in the CLI — not inside
`Engine::scan`.

**Rationale**: `Engine::scan` is infallible, synchronous, and offline by construction, and every one of those
is load-bearing (Principle V; contracts/core-api.md). A network call inside it would break all three and would
put an `Err` on a surface deliberately designed not to have one.

Placing the judge downstream also fits what 002 built. The judge needs exactly the things a `Verdict` already
carries — the observations, their spans, and the suppression channel to write into — and needs nothing that
was discarded on the way. That is a sign the boundary is in the right place rather than a convenience.

It costs one thing worth naming: the judge sees neutralised excerpts and the original input as separate
arguments, rather than the raw observation. That is the correct trade — FR-408 requires neutralised content —
but it means the judge cannot see anything a reader could not.

**Alternatives considered**: a tier inside the engine behind a feature flag — rejected, it puts network code
in the crate whose isolation is checked by CI, and the flag would be a compile-time answer to a runtime
question. A separate binary — rejected, it would duplicate target resolution and exit-code mapping, and
Principle V requires the CLI hold no logic the library lacks.

---

## Resolved unknowns

| Was open | Now |
|---|---|
| HTTP client and its weight | R1 — `ureq`, 22 crates, no executor |
| How a closed-enum answer is obtained | R2 — tool-use schema; proxies lacking it are `TierUnavailable` |
| What a judged verdict records | R3 — model id, prompt version, per-span features |
| Where the tier runs | R4 — after finalization, in the CLI |

**Deliberately still open**: how features combine into a score. Calibration needs the corpus (spec
Assumptions), and the first implementation holds the function trivial and obvious. Recording it here so that
`tasks.md` does not treat it as an oversight.
