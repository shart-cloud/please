# Plan: deepen frame-aware matching

Status: implemented for architecture recommendation 4 on 2026-09-12. Validation results are recorded below.

## Problem and intended result

Direct rule matching returns raw pattern matches. The engine builds observations, then asks
`detect::apply_frame` to remove ineligible ones through a callback into the matcher's rule lookup.
Decoded matching already checks frame eligibility inside the matcher. The two interfaces therefore
assign different responsibilities to their callers for the same `anchor = "frame"` rule declaration.

Concentrate rule frame eligibility in the matcher module. Both matching operations should return
only eligible results for the bytes they searched. Keep observation construction, original-input
attribution, quoting suppression, concealment, class filtering, and finalization in their existing
modules. This is a behavior-preserving refactor of shipping scans, not a change to frame definitions
or detection rules.

Current implementation locations:

- `src/matcher/mod.rs`: `find` returns occurrences; `matching_rules` applies frame eligibility and
  returns each matching rule once; `is_frame_anchored` supplies the direct path's callback.
- `src/matcher/patterns.rs`: bounded raw regex collection, lazy compilation, and coverage events.
- `src/engine.rs`: direct observation construction followed by the separate frame pass; decoded
  observations translate matches to original encoded spans.
- `src/detect/mod.rs`: `apply_frame` followed by independent `apply_suppression`.
- `src/structure.rs`: `FrameMap`, `QuotingMap`, and the shared local `frame_at` predicate.

The leverage is a smaller caller obligation: a rule match returned by the matcher has already met
its anchor requirement. Locality improves because neither the engine nor detect needs to look up
rule anchoring after an observation has been allocated.

## Interface and implementation decisions

Keep the two existing matcher operations with their distinct outputs:

- `find` returns every eligible `RuleMatch`, in the existing rule and occurrence order.
- `matching_rules` returns a rule once if any retained raw occurrence is eligible.

Use one private eligibility operation in the matcher, given the rule, searched bytes, match span,
and a lazily initialized frame map for those bytes. Both operations use it after bounded raw regex
collection. Unanchored rules bypass frame lookup. Build at most one frame map per matching operation,
and only when a frame-anchored rule has retained matches. Decoded candidates each get their own map.
Do not flatten decoded matching into `find` plus caller-side deduplication.

Keep `frame_at` in structure as the owner of frame syntax. Keep `FrameMap` as the lightweight,
on-demand predicate; do not restore a precomputed boundary vector. Do not introduce a configurable
matching strategy, generic callback interface, or new public scan-context type for this change.

The direct route will initially use the same lazy `FrameMap::build` approach as the decoded route.
This duplicates the JSON-shape probe already performed for quoting on inputs that reach frame
eligibility. That probe can scan the buffer, so measure JSON-shaped and long-whitespace inputs as
well as ordinary prose. If it produces a measurable regression, reuse structure's already-computed
frame metadata through a narrowly scoped internal route before landing; do not weaken timing gates
or add a second full structure analysis pass.

## Behavior that must remain fixed

| Concern | Required behavior |
|---|---|
| Eligibility | Off-frame hits appear in neither findings nor suppressions. |
| Quoting | Eligible quoted hits still reach quoting suppression; disabling suppression cannot revive an off-frame hit. |
| Caps | Count raw regex occurrences before filtering, including off-frame occurrences. Preserve the extra occurrence probe and its gap. |
| Zero cap | A raw regex match still records saturation, even if it would fail frame eligibility. |
| Exact cap | Exactly the configured number of raw hits does not itself imply saturation. |
| Direct coordinates | Eligibility and match spans use original input bytes, not sanitized excerpts. |
| Decoded coordinates | Eligibility uses the decoded buffer and its match offsets. Emitted evidence retains the original encoded-region span and transform chain. |
| Multiplicity | Direct matching returns occurrences; decoded matching returns one result per rule per candidate. |
| Quoted decoded text | Preserve existing exemption from original-input quoting suppression. Frame eligibility still applies inside the decoded bytes. |
| Other detectors | Structural and export observations retain their existing paths; they are not subjected to a new rule-ID/frame gate. |
| Coverage | Compile and match-limit events remain owned by the existing matching/finalization path, even when no eligible match survives. |
| Preparation | Preserve literal prefiltering, lazy built-in compilation, and retained caller-compiled patterns. |
| Verdicts | Preserve ruleset identity, finding order, classes, scores, suppression attribution, retained evidence, and display metadata. |

For example, with a cap of one, an off-frame first hit followed by an eligible second hit still
produces no accepted occurrence and a match-limit gap. Searching beyond the cap for an eligible hit
would change both detection behavior and bounded-work semantics and is outside this refactor.

## Incremental commits

### 1. Characterize the existing scan behavior and cost

Add focused public-engine regressions before changing production behavior. Use a small caller rule
set containing an anchored rule and an unanchored control, avoiding incidental built-in matches.
Disable unrelated transforms in direct-only tests and use an explicit encoding with controlled
transform depth for decoded cases.

Cover start-of-unit, middle-of-sentence, mixed off-frame/eligible hits, and repeated eligible hits.
Run these with caps of zero, one, exactly the raw count, and below the raw count. Assert retained
findings, suppressions, and coverage causes/details; checking only the final outcome is insufficient.
Assert decoded original spans, transform chains, and per-rule/per-candidate deduplication.

Extend the quoted-container cases across reference-analysis and enforcement/suppression-disabled
policies, including zero display limits. Preserve the existing live container, JSON, bracket,
HTML-comment concealment, and quoted-comment cases. A quoted positive must be reached and then
suppressed, not merely return clean because matching missed it.

Add focused benchmark workloads alongside the existing scaling benchmarks: many anchored hits,
mostly rejected off-frame hits, repeated decoded candidates, and JSON-shaped/whitespace-heavy
buffers. Capture a before baseline from this working tree, including prior recommendations, using
the same release profile and machine as the after measurement. Store measurements as development
evidence with source identity; do not use an older committed tree that lacks the current changes.

Acceptance: characterization tests pass before refactoring and a comparable performance baseline
exists. Do not claim performance equivalence from debug tests.

### 2. Centralize eligibility using the already-anchored decoded route

Introduce the private matcher eligibility operation and make `matching_rules` use it. Retain the
current lazy per-buffer frame map and the existing `PatternSet::matches` call and cap behavior.
This commit changes ownership inside the matcher without changing direct matching yet.

Add matcher-interface tests for anchored versus unanchored rules, mixed eligible/ineligible
occurrences, decoded deduplication, and coverage events. Keep engine-level characterization tests
as the long-lived behavior checks; avoid testing the private helper by mirroring its branches.

Acceptance: decoded behavior and all characterization tests remain unchanged; there is one matcher
implementation of the anchor decision.

### 3. Make direct matching enforce anchors and remove the engine's frame pass

Have `find` check each retained occurrence through the same eligibility operation before constructing
`RuleMatch`. Update engine observation construction to consume these already-eligible matches.
Remove the `detect::apply_frame` call and its rule-ID callback in the same commit, so frame filtering
never runs twice in the shipping route.

Delete the obsolete `detect::apply_frame` function and `Matcher::is_frame_anchored` lookup after
checking all repository references. Leave the separate quoting callback and suppression behavior
unchanged. Keep structural and export observation insertion, decoded composition, class filtering,
and finalization ordering intact.

Acceptance: no shipping caller enforces rule anchors after observation construction. Existing and
new tests preserve both channels and coverage details. Non-rule observations remain unaffected.

### 4. Record the changed placement and verify the complete path

Update the matcher and engine documentation, including the stale statement that decoded buffers
have no frame structure: they have their own structure, and their coordinates differ from the
original input. Separate the currently interleaved frame/suppression doc comments in detect.

Record an amendment to `specs/005-agentic-surface/plan.md` D2: rule data and frame-before-suppression
semantics stay; eligibility ownership moves from detect to matcher because direct and decoded
matching now share that responsibility. Preserve the historical reasoning rather than silently
rewriting it as though the original decision never existed. Link the amendment from the frame
contract documentation and use the domain terms in `CONTEXT.md`.

Run the validation below and compare the release measurements against step 1. Investigate any
repeatable slowdown beyond benchmark noise, particularly the extra direct JSON-shape probe.
Keep the existing performance thresholds; no performance-target changes belong in this work.

Acceptance: scan behavior is unchanged, the simpler matcher interface is documented, the old
callback coordination is gone, and before/after measurements satisfy the existing gates.

## Public interface compatibility

These modules are public Rust modules. Changing `Matcher::find` to return frame-eligible matches is
an intentional semantic strengthening of that low-level interface. Removing `detect::apply_frame`
and `Matcher::is_frame_anchored` is also a source-level change for external callers of those helpers.
The repository has no remaining need for them after migration; do not describe their removal as
private cleanup. Document the migration: consume frame-aware matcher results and retain quoting
suppression as a separate step. `Engine::scan`, rule schemas, CLI behavior, and verdict schemas keep
their existing contracts. Compatibility wrappers, if required by an external consumer, need an
explicit follow-up design rather than silently retaining a second acceptance implementation.

## Validation

Focused tests during the small commits, followed by:

```sh
cargo test -p please-core
cargo test -p please-cli --test cli --test contract --test rules_cli
cargo test --manifest-path crates/eval/Cargo.toml --features shipping-judge,shipping-ml --test product --test boundary
cargo clippy -p please-core --all-targets -- -D warnings
cargo build -p please-core --target wasm32-unknown-unknown
cargo fmt --all --check
bash ci/check-core-isolation.sh
bash ci/check-dependencies.sh
```

Run performance checks before and after on a quiet machine, without competing builds or tests:

```sh
cargo test --release -p please-core --test scaling -- --nocapture --test-threads=1
cargo bench -p please-core --bench scaling
```

Current release gates: growth exponent at most 1.15, 4 KiB p95 at most 10 ms, sustained throughput at
least 8 MB/s, and payload-dense cost at most 20 times benign cost. The historical 10 MB/s target is
separate from the 8 MB/s regression floor; passing the latter does not establish the former.
Retain existing seam checks for rule-index ownership, class filtering, and finalization. No live
judge or model-accuracy evaluation is required for this matcher refactor.

## Out of scope

No new frame delimiters, lexical introducers, rules, thresholds, decode transforms, or suppression
heuristics. No structural scanning of decoded buffers, new matching limits, coordinate remapping,
rule preparation changes, dependency additions, or verdict authority changes. Any observed detection
change is a regression to explain before proceeding, not an incidental improvement to fold in.


## Implementation — 2026-09-12

Both matcher operations now use one private frame-eligibility check after bounded raw pattern
collection. The engine no longer constructs observations only to discard them through detect's
frame callback. The obsolete public helpers were removed, and the D2 amendment and rule contract
record the low-level migration.

The initial implementation rebuilt direct frame metadata lazily. Benchmark comparisons flagged
JSON and whitespace-heavy workloads, so the final original-input route reuses the frame metadata
already held by `QuotingMap`, through a crate-private matcher entry point. This preserves the
old direct path's document-shape classification without another probe. Public `find` and each
decoded buffer retain independent lazy frame initialization. The metadata is copied only within
the scan of the same immutable input.

Characterization tests passed before the move. The final suites pass: 436 core tests, 45 CLI tests,
and 6 evaluation product/boundary tests. The new cases cover raw caps (zero/exact/overflow),
off-frame hits consuming a cap, unanchored controls, direct versus decoded multiplicity, original
encoded-region spans and chains, quoted encoded candidates, and quoting policies with zero display
limits. Clippy, WebAssembly compilation, formatting, core isolation, and dependency checks pass.

Release measurements and their limits are recorded in
`docs/research/frame-matching-2026-09-12.md` with source identities and raw benchmark output in the
accompanying JSON artifact. No live model or judge evaluation was run for this matcher change.
