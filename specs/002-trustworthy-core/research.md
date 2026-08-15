# Phase 0 Research: Trustworthy Core

**Feature**: `002-trustworthy-core` | **Date**: 2026-08-15

Every mechanism below was probed in a scratch crate before being adopted. Two of the six answers are not the
obvious one, and one design (P3) is only possible because the obvious approach fails to compile.

---

## P1 — Unforgeable provenance: a private field, not a public enum

**Decision**: `Provenance` is a public struct wrapping a private enum. Reading is public; constructing the
built-in variant is `pub(crate)` and reachable only from preparation.

**Rationale**: FR-104 requires provenance a caller cannot forge. The instinct is a public enum —
`enum Provenance { Builtin, Supplied }` — and it does not work: in Rust an enum's variants inherit the enum's
visibility, so a public enum has publicly constructible variants and there is no way to make one private. A
caller writes `Provenance::Builtin` and inherits the trusted fast path.

A public struct with a private field cannot be constructed externally at all: struct-literal syntax requires
every field to be visible, and there is no derived constructor. So the only way in is a function, and functions
have per-item visibility. Verified:

```rust
pub struct Provenance(Kind);              // Kind is private
impl Provenance {
    pub(crate) fn builtin() -> Self { … }  // preparation only
    pub fn supplied() -> Self { … }        // anyone
    pub fn is_builtin(&self) -> bool { … } // reading is public
}
```

This also answers loss #4 from the review — the identity digest can cover provenance because provenance is a
value, not an assertion.

**Alternatives considered**: Public enum — rejected, variants cannot be made private. A `sealed trait` — works
but adds a trait and an impl for what is one bit of information. A `bool is_builtin` field — same forgeability
problem as the enum, plus it loses room for a third origin later.

---

## P2 — Prepared-rule-set safety: a newtype, not type-state

**Decision**: `PreparedRuleset` is a distinct type with a private field. Every constructor performs the
validation FR-102 requires. An engine can be built from nothing else. No generic type parameters.

**Rationale**: Both type-state and a newtype give a compile-time guarantee; the question is what each costs. A
type-state (`Ruleset<Unvalidated>` → `Ruleset<Validated>`) buys the ability to be *generic over the validation
state*, which is useful when many operations are valid in several states. Here there is exactly one transition
and exactly one consumer, so the generic parameter would appear in every signature that touches a rule set and
buy nothing. The newtype gets the same "there is no path that skips validation" property because that property
comes from *the constructors*, not from the type parameter.

The distinction that matters for FR-103: safety must not depend on call order. Both approaches deliver that,
because in both cases the unvalidated form is simply not accepted where an executable capability is built. What
makes it real is deleting the public `validate_compiled` — while a caller *can* call it separately, some caller
will forget, which is precisely the current situation.

**Alternatives considered**: Type-state with a phantom parameter — rejected as generic noise for a single
transition. A runtime `validated: bool` checked at construction — rejected; it moves the failure from compile
time to run time for no gain. Keeping `validate_compiled` public *and* validating internally — rejected: two
ways to do one thing, and the public one implies the internal one is optional.

---

## P3 — Verdict types move inside finalization, because the obvious approach does not compile

**Decision**: `Verdict`, `Reason`, and `Incompleteness` are defined in modules *inside* `finalize`, with
`pub(super)` constructors. They are re-exported for public reading. Detectors cannot construct them.

**Rationale**: This is the finding that changed the design. FR-121 requires that a detector be unable to
construct a reported reason, and the precise tool for that looks like `pub(in path)` visibility:

```rust
// in crate::verdict
pub(in crate::finalize) fn new(…) -> Self   // ← does not compile
```

`error[E0433]: could not find 'finalize' in the crate root`. Rust's `pub(in path)` restricts visibility only
to an **ancestor** of the item; it cannot name a sibling. Visibility narrows up the module tree, never
sideways. So a type living in `crate::verdict` cannot be made visible to `crate::finalize` and hidden from
`crate::detect` — they are peers.

The constraint forces the better layout. If only finalization may construct a verdict, the verdict types belong
*to* finalization, and then ordinary `pub(super)` does the job. Verified, including that forgery is a hard
error rather than a lint:

```
error[E0624]: associated function `new` is private
  pub fn forge() -> Reason { finalize::types::Reason::new("x".into()) }
                                                    ^^^ private associated function
```

Detectors deal in observations; finalization turns observations into reasons. That was already the intended
architecture — the compiler simply refused the version of it that left the types in the wrong place.

The public reading path stays stable via `pub use finalize::types::{Verdict, Reason, …}`, so embedders see no
change in how they name these types.

**Alternatives considered**: `pub(in crate::finalize)` — does not compile, above. `pub(crate)` constructors —
compiles but grants every module in the crate the right to construct, which is the status quo. A builder trait
implemented only by finalization — works, but adds indirection to achieve what module placement achieves
directly.

---

## P4 — The rule index space lives in one matcher, and never leaves it

**Decision**: The literal prefilter and the pattern store merge into one `matcher` module owning the rule
slice, the prefilter, and the compiled-pattern slots. Its interface yields observations carrying a rule
reference; no positional identifier crosses a seam.

**Rationale**: Three components currently agree on an array position into `all_rules()`, and they agree only
because one function builds all three from the same slice. Nothing enforces it. The failure mode is silent and
severe — a real detection reported with another rule's identity, severity, and description — and no existing
test would catch it, because every test constructs all three together.

Merging is the fix rather than a `RuleIndex` newtype. A newtype makes the index harder to *confuse* with
another integer, but it still crosses seams, so three components still have to agree about what it indexes.
Deletion test: delete the matcher and the index bookkeeping reappears in three places, which is where it is
today.

**Alternatives considered**: A `RuleIndex` newtype minted only by the rule set — better than a bare `usize`,
but the coupling survives. Keying by rule id string — correct but pays a hash lookup per candidate per scan on
the hot path, for a guarantee module placement gives free.

---

## P5 — Retained compilation: pre-fill the lazy slot

**Decision**: Validation compiles each caller-supplied pattern and stores it into the same slot the match path
reads. Built-in patterns are left empty and compile lazily on first use.

**Rationale**: FR-109 forbids compiling a rule twice, and today we do exactly that: validation builds a pattern
to prove it is within budget and drops it, then matching compiles the identical pattern again on first use.
`OnceLock::set` makes retention trivial — a filled slot is indistinguishable at the read site from one filled
lazily. Verified that a pre-filled slot's initialiser is never invoked:

```rust
s.prefill(0, compiled);
s.get(0, || panic!("must not recompile"));   // passes
```

The asymmetry is the point, and it preserves both budgets measured in 001 research D17:

| Path | Validated at | Compiled | First scan |
|---|---|---|---|
| Built-in | CI, at default limits | lazily | cold start stays ~4 ms |
| Caller-supplied | construction | retained | already warm |

**Alternatives considered**: Compile everything eagerly — rejected, 44 ms for 80 rules against a 25 ms
cold-start budget. Validate without compiling by estimating program size from the parsed syntax — rejected in
D17 already: it means reimplementing the compiler's size accounting and being silently wrong about it.

---

## P6 — Evidence is write-only to detectors, read-only to finalization

**Decision**: One `Evidence` accumulator, passed to detectors as a handle exposing only *record* operations.
Finalization owns it, is its only reader, and is the only thing that turns it into a verdict.

**Rationale**: FR-122 requires one coverage-gap vocabulary recorded where the gap occurs, and FR-123 forbids a
decoder judging what counts as a gap. Both follow from giving detectors a handle they can write to and cannot
read: `note_bound(cause, configured, detail)` and `note_failure(cause, detail)` are calls at the site that
knows *why*, which replaces four detector-specific shapes (`Expansion { depth_exceeded, fanout_exceeded }`,
`RuleMatches { saturated }`, `(String, bool)`) and the translation table in `scan` that currently converts
them.

The write-only asymmetry matters for FR-124. Today aggregate-before-truncate is maintained as two collections
a caller must keep in sync; a detector that forgets one push silently lowers the score. If detectors cannot
read the accumulator, they cannot maintain a parallel view of it, so the score can only be derived from the one
collection that exists. The bug class disappears rather than the bug.

`ScanPlan` (FR-129) is the mirror image: read-only to detectors, resolving the active class set once so no
later stage re-decides it. That single resolution is what fixes the double-gate defect — the filter has one
application site rather than two that must agree.

**Alternatives considered**: Detectors returning typed gap values for orchestration to record — rejected, it
keeps a translation step and therefore keeps the possibility of forgetting one. A trait each detector
implements — deferred: that is the uniform-detector seam the architecture review rated Speculative, and it
should wait until the classifier tier makes a second adapter real.

---

## P7 — Migration order: two behaviour changes, separately, in the middle

**Decision**: Nine steps. Steps 1–3 and 7–9 are behaviour-preserving; steps 4 (validation enforcement) and 5
(class removal) change behaviour and land as their own commits with their own tests. Sealing constructors is
last.

**Rationale**: Sealing early breaks every subsequent step, so it goes last even though it is the guarantee the
feature exists for. The two behaviour changes are separated because they fail differently: enforcement makes a
previously-accepted rule set fail to load, and class removal changes what a verdict says. Bisecting a
regression across a commit that did both would be miserable.

SC-113 requires accuracy to be unchanged, which gives a natural checkpoint: fixture detection and
false-positive counts are recorded before step 1 and compared after step 9. Any movement is a bug in this
feature, not a tuning question — and it is the only cheap way to catch a refactor that quietly changes what
gets found.

| Step | Change | Behaviour |
|---|---|---|
| 1 | Introduce `finalize` with the verdict types moved inside it; re-export for readers | preserving |
| 2 | Route all three verdict-construction sites through finalization; delete the parts struct | preserving |
| 3 | `Evidence` accumulator; detectors record gaps directly; remove the translation table | preserving |
| 4 | **Preparation enforces compiled validation on caller rules; retention fills slots** | **changes** |
| 5 | **Remove the `Encoding` class; one class filter in the plan** | **changes** |
| 6 | Merge prefilter and pattern store into `matcher`; index space becomes private | preserving |
| 7 | Delete the parallel hit collection; score derives from the accumulator | preserving |
| 8 | Delete the duplicate ordering definition | preserving |
| 9 | Seal constructors: `pub(super)` on verdict types, provenance private, `validate_compiled` removed from the public surface | preserving |

**Alternatives considered**: Class removal first, since it is the smaller change — rejected: it touches the
same dispatch code step 3 rewrites, so doing it first means doing it twice. Sealing first to get the guarantee
early — rejected, it does not compile until the moves are done.
