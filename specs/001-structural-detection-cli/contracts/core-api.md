# Contract: `please-core` embedding surface

**Feature**: `001-structural-detection-cli`

The Rust-facing contract. Its first real consumer is a bee `LoopHook`, and Principle V requires the
CLI to be a thin wrapper over exactly these entry points — so anything `plz` can do, an embedder can
do, and no detection logic exists only in the binary.

Types are described in terms of the [data model](../data-model.md); this document fixes the shape of
the surface, not its implementation.

---

## Shape

```rust
// Compile a rule set once; reuse the engine for many scans.
Engine::builtin() -> Result<Engine, RulesetError>
Engine::from_toml(&str) -> Result<Engine, RulesetError>
Engine::builder() -> EngineBuilder     // add rule sets, suppress by id

// Scan. Infallible: every failure mode is a Verdict, not an Err.
Engine::scan(&self, input: &[u8], policy: &ScanPolicy, target: TargetRef) -> Verdict

Verdict::outcome(&self) -> Outcome
Verdict::reasons(&self) -> &[Reason]
Verdict::incomplete(&self) -> &[Incompleteness]
Verdict::is_at_or_above(&self, RiskLevel) -> bool
```

### `scan` returns `Verdict`, never `Result`

The deliberate choice on this surface. Everything that could be an error is instead an outcome the
caller must read: oversized input, a failed decode, an exhausted bound. There is no `Err` for an
embedder to `unwrap_or_default()` into a clean verdict — the type system does not offer a path from
"analysis failed" to "input is fine".

Rule-set *construction* does return `Result`, because a malformed rule set must fail loudly and
before any scanning (FR-024). The split is: configuration errors are `Err`, analysis outcomes are
`Verdict`.

### `Engine` is `Send + Sync` and holds no interior mutable state visible to callers

One engine serves concurrent scans. Lazy pattern compilation (D4) is cached behind internal
synchronisation, so a compiled pattern is shared rather than recompiled per scan. Compilation is
memoised, never invalidated — a scan's result cannot depend on how many scans preceded it, which
FR-020 requires and FR-030 makes observable.

### No clock, no filesystem, no network

`please-core` uses no `std::time`, opens no files, and makes no network calls. Reading a target is
the caller's job; the core takes bytes. This is what keeps the `wasm32-unknown-unknown` build honest
(D10) and what CI proves on every change.

`Engine::from_toml` takes a string rather than a path for the same reason: rule-set *loading* is I/O
and belongs to the caller.

A consequence worth stating: because the core never opens a file, `target_unreadable` is a cause the
**caller** records, not one the engine can produce. An embedder walking a directory is responsible for
constructing an inconclusive verdict for a target it could not read, exactly as `plz` does (FR-032a).
The engine supplies the vocabulary; whoever does the I/O has to use it. Skipping the file instead is
the one thing that must not happen — it reintroduces the fail-open the outcome model exists to close.

---

## Bytes in, not `&str`

`scan` accepts `&[u8]`. Scan targets are untrusted and frequently not valid UTF-8 — a truncated tool
result, a binary file, a deliberately malformed encoding. Requiring `&str` would push the caller into
a lossy conversion or a rejection before analysis, and "this input was not valid text" is a fact the
scanner should report rather than a reason to refuse to look.

Invalid sequences are handled internally and recorded, not rejected.

---

## Feature flags

| Feature | Default | Effect |
|---|---|---|
| `serde` | off | `Serialize`/`Deserialize` on the verdict types |
| `std` | on | Off is reserved for a future no-std path; not exercised in this slice |

`serde` is off by default so the wasm and embedded builds do not pay for it. `please-cli` enables it.
The dependency guard test (D11) asserts the default build's resolved dependency set against a
committed allow-list, so this stays true without relying on review.

---

## Stability

The verdict types and `Engine::scan` are the published surface; the detector internals are not.
Adding a `DetectionClass` variant or a `Transform` kind is a breaking change for exhaustive matching,
so those enums are marked non-exhaustive from the outset — the set of things an attacker does grows,
and the first addition should not break every embedder.

---

## Reference embedding: a bee `LoopHook`

The integration this contract is shaped for. bee's `LoopHook` observes `StepEvent` and returns
`Flow`; `StepEvent::AfterToolResult` carries the tool output where indirect injection actually
arrives, and `Flow::Deny(String)` is how a hook refuses.

```rust
// Illustrative — the real integration is its own feature.
async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
    let StepEvent::AfterToolResult { result, .. } = ev else { return Flow::Continue };
    let verdict = self.engine.scan(result.as_bytes(), &self.policy, TargetRef::buffer("tool_result"));
    match verdict.outcome() {
        Outcome::Clean => Flow::Continue,
        Outcome::RiskFound if verdict.is_at_or_above(self.threshold) =>
            Flow::Deny(verdict.summary()),
        Outcome::RiskFound => Flow::Continue,          // below this deployment's bar
        Outcome::Inconclusive => self.on_inconclusive, // policy, not engine
    }
}
```

The `Inconclusive` arm is the point of the whole three-outcome design: the hook must state a policy
for "could not analyse", and the compiler will not let it forget the case exists. A two-outcome model
would have made that arm invisible and defaulted it to `Continue`.

Note also that `scan` is called with no `.await` and no runtime — Principle V's runtime-free
requirement is what allows a synchronous call inside bee's async hook without dragging an executor
into the core.
