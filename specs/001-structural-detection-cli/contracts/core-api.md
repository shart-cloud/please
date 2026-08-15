# Contract: `please-core` embedding surface

**Feature**: `001-structural-detection-cli`

The Rust-facing contract. Its first real consumer is a bee `LoopHook`, and Principle V requires the
CLI to be a thin wrapper over exactly these entry points — so anything `plz` can do, an embedder can
do, and no detection logic exists only in the binary.

Types are described in terms of the [data model](../data-model.md); this document fixes the shape of
the surface, not its implementation.

> **Corrected by feature 002 (FR-152).** Five things here no longer matched the implementation, each marked
> below. One thing FR-152 expected to find was **not** here: it names "the claim that an engine may be
> cloned", and this document never made it. `Engine` derives `Debug` only, and the code comment beside it has
> always said cloning would silently discard the memoised patterns and re-pay compilation — share it behind an
> `Arc`. Recording the absence rather than inventing a correction, because a spec that fixes a defect it does
> not have is a spec nobody can check.

---

## Shape

```rust
// Prepare a rule set, then build a scanner from it. Preparation is the ONLY route: every entry point
// validates, so there is no call order for a caller to get wrong (002 FR-102, FR-103).
prepare::builtin() -> Result<PreparedRuleset, RulesetError>
prepare::from_source(&str, RulesetLimits) -> Result<PreparedRuleset, RulesetError>
prepare::layered(Option<Ruleset>, Vec<Ruleset>, &[String], RulesetLimits)
    -> Result<PreparedRuleset, RulesetError>
Engine::prepared(PreparedRuleset) -> Engine          // infallible: the proof already happened

// Conveniences over the above. Same guarantees, fewer words.
Engine::builtin() -> Result<Engine, RulesetError>
Engine::from_toml(&str) -> Result<Engine, RulesetError>
Engine::builder() -> EngineBuilder     // add rule sets, suppress by id

// Scan. Infallible: every failure mode is a Verdict, not an Err.
Engine::scan(&self, input: &[u8], policy: &ScanPolicy, target: TargetRef) -> Verdict

Verdict::outcome(&self) -> Outcome
Verdict::score(&self) -> u8
Verdict::risk(&self) -> RiskLevel
Verdict::reasons(&self) -> &[Reason]
Verdict::reasons_truncated(&self) -> bool
Verdict::suppressed(&self) -> &[Reason]              // 002 FR-128: what quoting hid, and why
Verdict::suppressions_truncated(&self) -> bool
Verdict::incomplete(&self) -> &[Incompleteness]
Verdict::is_at_or_above(&self, RiskLevel) -> bool
Verdict::summary(&self) -> String

// Verdicts for targets the core cannot examine itself. The caller does the I/O, so the caller
// records the outcome — see the note on `target_unreadable` below.
finalize::unreadable_target(TargetRef, impl Into<String>, RulesetId) -> Verdict
finalize::oversized(u64, usize, TargetRef, RulesetId) -> Verdict
```

> **Correction 1 (002).** `Engine::builtin` and `Engine::from_toml` were the whole construction surface here.
> They remain, but as conveniences: the thing they wrap is `prepare`, and stating only the conveniences hid
> the guarantee. `Reason`'s fields are also accessor methods now rather than public fields, so that only
> finalization can construct one (002 FR-121).

### `scan` returns `Verdict`, never `Result`

The deliberate choice on this surface. Everything that could be an error is instead an outcome the
caller must read: oversized input, a failed decode, an exhausted bound. There is no `Err` for an
embedder to `unwrap_or_default()` into a clean verdict — the type system does not offer a path from
"analysis failed" to "input is fine".

Rule-set *construction* does return `Result`, because a malformed **or resource-exhausting** rule set must
fail loudly and before any scanning (FR-024, as amended). The split is: configuration errors are `Err`,
analysis outcomes are `Verdict`.

> **Correction 2 (002).** This said "malformed" alone, matching FR-024 as originally written. A
> resource-exhausting rule is well-formed — `a{1000}{1000}{1000}` parses in microseconds and compiles to an
> automaton with ~10⁹ states — so the sentence described neither the threat nor, at the time, the code.

### Validation has two tiers, and only one of them is optional to *pay for*

| Tier | When | Cost, 80 rules | Catches |
|---|---|---|---|
| Syntax parse | every load, always | ~3.9 ms | look-around, backreferences, malformed patterns |
| Full compile | every **caller-supplied** rule, at preparation | ~44 ms | the above, plus counted-repetition size bombs |

The expensive tier is **not** skippable. What varies is *who has already paid*: built-in rules are proven by a
CI check at default limits and compiled lazily on first literal hit, so cold start is unaffected;
caller-supplied rules are compiled at preparation and the compiled form is **retained** as the executable
matching state, so no rule is compiled twice (002 FR-109).

Limits stricter than the ones a validation record was established at force revalidation, including for
built-in rules (002 FR-108). Relaxing them does not: a pattern that fits a small budget fits a larger one.

> **Correction 3 (002).** This document did not mention the two tiers at all. 001 implemented them and exposed
> the expensive one as a separate public `Ruleset::validate_compiled` that nothing called, so the surface a
> reader saw here was safe and the one they got was not.

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

`serde` is off by default so the wasm and embedded builds do not pay for it. `please-cli` enables it.

> **Correction 4 (002).** A `std` feature was listed and has never existed — `crates/core/Cargo.toml` declares
> `default` and `serde` and nothing else. A caller writing `default-features = false, features = ["std"]` on
> the strength of this table would have got a hard error. The no-std path is still worth wanting; it is not
> pending, it is unstarted.
The dependency guard test (D11) asserts the default build's resolved dependency set against a
committed allow-list, so this stays true without relying on review.

---

## Stability

The verdict types and `Engine::scan` are the published surface; the detector internals are not.
Adding a `DetectionClass` variant or a `Transform` kind is a breaking change for exhaustive matching,
so those enums are marked non-exhaustive from the outset — the set of things an attacker does grows,
and the first addition should not break every embedder.

> **Correction 5 (002).** `non_exhaustive` protects against *additions*. Feature 002 **removed** the
> `Encoding` variant, which no amount of `non_exhaustive` makes compatible: an embedder matching on it stops
> compiling, and one comparing `class.as_str() == "encoding"` silently stops matching anything. It was removed
> anyway, because it named a delivery mechanism rather than a kind of finding and was the cause of a shipped
> defect in class selection — `docs/limits.md` and 002's data model carry the argument. Stating it here so the
> compatibility cost is on the record next to the compatibility claim.
>
> **Correction 6 (003).** The set has now changed twice — `Encoding` removed, `AgentDirected` added — which is
> the pattern worth naming rather than the individual edits. `non_exhaustive` makes the addition compatible
> for `match`, and does nothing for either change to an embedder comparing `class.as_str()` against a literal.
> Anyone doing that should be reading `policy::ALL_CLASSES` instead.

---

## Reference embedding: a bee `LoopHook`

The integration this contract is shaped for. bee's `LoopHook` observes `StepEvent` and returns
`Flow`; `StepEvent::AfterToolResult` carries the tool output where indirect injection actually
arrives, and `Flow::Deny(String)` is how a hook refuses.

```rust
// Illustrative — the real integration is its own feature.
async fn on_event(&self, ev: &StepEvent<'_>) -> Flow {
    let StepEvent::AfterToolResult { result, .. } = ev else { return Flow::Continue };
    let verdict = self.engine.scan(
        result.as_bytes(),
        &self.policy,
        // Two arguments: a name and a byte count. The first version of this example passed one and would
        // not have compiled — worth fixing, since this snippet is what an integrator copies.
        TargetRef::buffer("tool_result", result.len()),
    );
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
