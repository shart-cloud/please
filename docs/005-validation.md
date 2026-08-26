# Feature 005 — validation record

What was claimed, what was measured, and what is still open. Companion to
`docs/005-accuracy-baseline.txt` (the before) and `docs/research/frame-cost.md` (the measurement that
gated the feature).

## Provenance

| | |
|---|---|
| before | `cd1c131`, rule-set digest `3f5b7d5ab13ee9e2` |
| after | this branch |
| corpus | 14 slices, ~74,000 rows, floor `low` |
| reproduce | `cargo test --workspace`; `cd crates/eval && cargo run --release -- run && … gate` |

The "before" column throughout was measured from a **binary built at `cd1c131` in a separate worktree**,
not from remembered numbers. Two of the results below reverse conclusions that remembered numbers would
have produced.

---

## Success criteria

| | claim | result |
|---|---|---|
| SC-501 | five of six probed attacks detected, up from one | **met — six of six** |
| SC-502 | identical verdict at every frame position, three payloads | **met** (`tests/frame.rs`) |
| SC-503 | frame costs ≤ 1 false positive on OR-Bench + stratified non-adversarial | **met** — 0→0 and 130→134 of 12,769, both 1.0% |
| SC-504 | no per-source detection falls | **met — zero of 41 fell; 15 rose** |
| SC-505 | no unsuppressed finding on hand-written repo text | **partially met** — 8 non-clean of 25 → 5 of 31, see below |
| SC-506 | agentic corpus reported separately | **not done** — see "not delivered" |
| SC-507 | ≥8 hard negatives, one per vector | **partially met** — 4 authored (`tests/privilege.rs`), not 8 |
| SC-508 | 16 class × delivery combinations | **met** (`tests/classes.rs`, extended to 8 classes) |
| SC-509 | no throughput regression | **not met** — ~9.1 → ~8.2 MB/s, above the 8.0 floor, recorded |
| SC-510 | wasm32 + 27-crate pin hold | **met** |

## Detection, measured

| slice | before | after |
|---|---:|---:|
| generated corpus | 206 | **316** |
| LLMail-Inject | 10,562 | **10,925** |
| stratified adversarial | 1,703 | **1,757** |
| ObfuscationAugmenter | 409 | **444** |
| InjecAgent | 442 | 442 |
| fixture positives | 43/51 | 43/51 |

`phrase-role-01`: **0.0% → 98.1%**. One of the sixteen payloads `eval-baseline.md` §6 recorded as
detected nowhere, with not a word of it changed.

## False positives, measured

| slice | before | after |
|---|---:|---:|
| OR-Bench | 0.0% | 0.0% |
| stratified non-adversarial | 1.0% | 1.0% |
| multilingual | 0.6% | 0.6% |
| hand-written benign | 5.0% | 5.0% |
| this repository's prose | 31.1% | **30.4%** |

`please-eval gate` **passes**.

## What the feature shipped

1. **The frame** (FR-501–505) — `anchor = "frame"` as rule data, one shared definition of where a
   semantic unit begins, replacing four drifted copies of a hand-written prefix class.
2. **`Privilege`** (FR-506–511) — the eighth class, for content widening the agent's own authority.
3. **Three rules** (FR-512–515) — `privilege.permission_widening`,
   `external_action.remote_execution`, and an extended `solicitation.credentials`.
4. **Non-text targets** (FR-516–518) — declined to the `incomplete` channel in the CLI, never the core.
5. **Amendments** (FR-522–525) — schema, data model, core-api, `docs/limits.md` including a retraction.

## Three defects found that the feature was not looking for

- **`docs/limits.md` claimed a guarantee that was not holding.** "An HTML comment must never become a
  quoting context", status *enforced by test*. The tests asserted the suppression layer's half, which
  was always true; nothing asserted that a rule could *reach* inside a comment, and no line-anchored rule
  could. Retracted in place.
- **PLEASE's own rule-set digest was a suppression bypass.** `3f5b7d5ab13ee9e2` has letters on both sides
  of interior digits, which enabled a whole-document leetspeak fold — an unsuppressable copy of any
  document quoting a verdict. Isolated to that single token in a 22 KB file.
- **A literal that is a prefix of another literal silently disabled its rule.** The prefilter iterated
  non-overlapping, so `bypass` (declared in 001) shadowed `bypasspermissions` (declared in 005) and the
  privilege rule was never evaluated. Shipping since the first commit.

## Two measurements that nearly ended the feature

Both caught by the Phase 4 gate, neither visible to review. Full detail in `frame-cost.md` §3.

- Folding the rules' lexical directive introducers under the frame cost **228 of 442 InjecAgent
  detections**. The repair was to split each rule in two, one mechanism each.
- The frame's line-start marker set inherited `]` from the 001 prefix class and not `[`. **SPML fell from
  100% to 13%**, TensorTrust from 100% to 52%.

## Not delivered, and why

- **FR-519/SC-506 — the purpose-authored agentic corpus is not built.** The constitution requires it to be
  reported separately from public-corpus metrics, and that separation is not implemented in
  `please-eval report`. This is the largest piece of the specification left undone. Everything claimed
  above is measured on the existing slices plus the six-payload probe, and the probe is **six payloads,
  not a rate** — it must be quoted as a fixture result.
- **SC-507 — four hard negatives, not eight.** They cover the `privilege` class, which is the one whose
  justification depended on them. The other vectors' negatives are not written.
- **SC-505 is partially met.** Five hand-written targets still report: `rules/builtin.toml` and
  `rules/experimental/actionable-directive.toml` (which contain the patterns they define — not fixable
  and arguably should not be), `docs/limits.md` and `docs/005-accuracy-baseline.txt` (payload
  catalogues), and `docs/research/indirect-structure.md`. The six binaries are now correctly declined
  rather than scored.
- **Two predicted fixture closures did not happen.** `indirect-email-007` and `indirect-skill-002` were
  named in the specification as frame cases and are not; the corrections are in `frame-cost.md` §6 and
  `docs/limits.md`.
- **SC-509 is not met.** Throughput fell about 10%. It is above the enforced floor and recorded.

## One decision this feature made that it now argues was wrong

The specification rejected a `--surface` hint on evidence: it probed a real `AGENTS.md` and `CLAUDE.md`,
found both clean, and concluded there was no false-positive pressure to relieve.

That was true, and it was the wrong question. `indirect-repo-cursorrules-001` — the AIShellJack
rules-file backdoor — is still missed, because its payload sits in inline code and quoting suppression
excuses it. In a README that is correct. In a `.cursorrules`, which is configuration an agent executes,
the fenced command *is* the command. The pressure is a **false negative**, and the probe was not built to
see it.

Recorded in `docs/limits.md` rather than patched, because re-opening the decision deserves its own
measurement.
