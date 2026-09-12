# Review authority and request binding — 2026-09-11

This implements the next architecture-review slice after bounded acquisition and classifier window
preprocessing. It deliberately changes the judge's default decision semantics.

## Caller authority

`plz scan --judge` obtains an advisory review. Recommendations are recorded, but active findings,
score, risk, and the resulting exit status remain governed by detection evidence. To authorize
demotions to lower that result, use `--judge --judge-allow-release`. All findings demoted under this
authority can produce `Clean` and exit 0; coverage gaps still prevent a clean result.

Library callers make the same choice with
`Judge::new(resolution).with_authority(ReviewAuthority::MayRelease)`. It applies to ordinary review,
ML-only review, and the combined contextual route. Default authority is `Advisory` on all three.
Offline ML response application likewise defaults to advisory; the methods ending in
`_with_authority` require the caller's explicit choice. Ordinary and ML reports record `authority`.

This is an enforcement policy choice, not a model safety claim. An authoritative reviewer may be
manipulated into releasing an attack. Existing research measurements describe their original
configuration and do not establish attack release rates or benign interruption rates for this one.
Future evaluations must name the authority setting and measure both costs.

## Request binding

Ordinary request assembly verifies the complete-input digest before sending evidence. Verdicts
retain the exact band table used by finalization. Compatibility APIs accepting a band table reject
a mismatch; the new authority-aware finalizer uses the retained table directly. Coverage-only
composition preserves calibration.

A `ReviewScope` captures input identity, policy, ruleset, engine, ML attribution, active evidence,
and prior suppressions before the request. Application checks exact equality of those facts.
Coverage gaps may be added while a request is pending and survive application. The scope retains
the original evidence separately from the decisions, including after an authorized demotion.

Wire span IDs are opaque hashes tied to this captured request, replacing reusable `s0` positions.
Responses carrying another request's IDs fail parsing. Prompt version is now `2026-09-11.5`;
the changed IDs are part of model input and require evaluation before reusing old accuracy claims.
Report `request_id` and `evidence_ids` identify the original namespace; historical `reason_index`
refers to that namespace, not to the possibly shortened post-review list.

For direct host composition, capture `ReviewScope` before obtaining decisions and use its `report`
method with `EvidenceDecision` IDs. The compatibility `bind` method accepts positional reports in
that captured namespace. Unbound reports and duplicate or contradictory decisions are refused
atomically, preserving findings and adding a gap. Request fields are read-only outside the judge
crate. Low-level synthetic evidence can be bound without inventing input provenance, but the
network API requires an actual matching scan digest.

Scope hashes identify this version of the in-memory representation; exact scope equality enforces
binding. They are not authentication tokens or a persistent cross-version inference identity.

## Remaining work

Follow-up: [retained analysis and report projection](retained-analysis-2026-09-11.md) now resolves
the reason-list truncation limitation described below. The rest remains follow-up work.

This is an incremental binding repair, not the retained `Analysis` redesign. Finalized reason-list
truncation still prevents review and ML composition. Evidence IDs are stable within a captured
review, not yet a detector-wide identity across arbitrary pipeline transformations. The next step
is retained analysis and a final reporting projection, followed by a shared product/evaluation
pipeline, complete inference identity, and calibrated decision policy.
