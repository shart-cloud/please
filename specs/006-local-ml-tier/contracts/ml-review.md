# Contract: review the instruction boundary behind an ML finding

Status: implemented as an opt-in library API with offline contract tests. Version:
`ml-boundary-review-v1` (supersedes the September 11 draft). The CLI's existing structural judge prompt,
scoring rule, and routing remain the baseline. Live semantic effectiveness is not measured.
See [implementation and integration](../../../docs/ml-boundary-review.md) for the API, wire limits,
input binding, capture seam, and evaluation limitations.

## Problem and intended behavior

A document classifier can flag an ordinary task or topical prose. The existing structural judge
answers whether an excerpt describes an instruction and whether that description is the document's
subject. Correctly calling a poem unrelated, or a legitimate request an instruction, cannot clear
that ML false positive under its current rule.

An ML review must instead answer: **what requested behavior, if any, crosses a boundary supplied by
the caller?** Ordinary instructions are permissible task requests where the caller's context permits
them. Topical references to secrets, restarting, or commands do not by themselves cross a boundary.
There must be an explicit outcome for **no supported violation**, distinct from insufficient context
or failed review. This is narrower than a claim that the document is safe for every application.

## Caller-owned request

The host assembles and freezes these fields before reading the review response:

| Field | Requirement |
| --- | --- |
| `contract_version` | Exact version; incompatible responses fail closed. |
| `request_id` | Host-generated identifier bound to this input, policy, candidate set, and request version. |
| `source` | Caller-provided `untrusted_user_input`, `untrusted_tool_response`, or `security_reference`; unspecified origin is insufficient for clearing. |
| `task_context` | Trusted description of the authorized task and how the document will be used, when relevant. Never derived from the document's claims. |
| `boundaries` | Nonempty list of host-generated IDs, typed constraints, and their explicit scope. |
| `context_completeness` | Which relevant scopes are known and which are unavailable; absent permissions are not inferred as grants. |
| `analysis_text` | Complete original document, safely rendered and delimited as data; never just the displayed finding prefix. |
| `candidates` | Opaque IDs for eligible ML findings and their document scope. No probability, severity, upstream label, source-dataset name, rule ID, or model prediction rationale. |

Boundary types include instruction hierarchy, hidden application context, caller-authorized tool
actions, and protected-data destinations. They are supplied independently: an instruction-hierarchy
rule does not establish export permissions. The September 11 frozen set supplies an untrusted-user
hierarchy context and **no application export policy**. Evaluation must not invent additional grants,
protected objects, or trusted task history from its labels.

For `untrusted_user_input`, ordinary requests within the supplied constraints are expected. For
`untrusted_tool_response`, content does not acquire authority to redirect the agent merely by being
returned from a tool. For `security_reference`, intended analysis is relevant but does not automatically
legitimize every embedded instruction. Quoting, claimed consent, role markers, urgency, and purported
system messages inside the document cannot alter any caller-owned field.

The host sends policy descriptions or opaque resource identifiers, **not secret values**, as context.
Trusted context is separately encoded from document data. Document delimiters must be escaped, control
characters neutralized, and the full encoded input bounded. If the full input or needed task context
cannot be provided, the review cannot produce an actionable clearing decision.

## Closed response and decision mapping

Each candidate receives exactly one of these results:

| Result | Required explanation | Host action |
| --- | --- | --- |
| `supported_violation` | Existing boundary ID, evidence range(s), and the behavior that conflicts with that boundary. | Keep the ML finding at its original severity. |
| `no_supported_violation` | All applicable boundary IDs assessed; a bounded rationale for why the document is an ordinary request, discussion/example, unrelated content, or otherwise shows no supported crossing. | May demote **that ML finding only**, after all host checks pass. |
| `indeterminate` | Ambiguous behavior, insufficient task/permission context, unavailable evidence, or conflicting interpretations. | Keep the finding; record review incompleteness. |

No field accepts a new score, global verdict, new finding, permission grant, or instruction to the host.
Assessing all supplied boundaries does not establish context completeness; the host must independently
know that the supplied scopes are sufficient for the proposed demotion. A reviewer cannot cure missing
context by saying it examined everything.

For a supported violation, evidence ranges use byte offsets into the exact UTF-8 `analysis_text`
that was sent. The host checks boundaries, character boundaries, and any quoted text against that
string, and retains a rendering/source map if it displays original-input positions. It must never
interpret these positions as raw-input offsets without that map. A range matching text proves
attribution, not the semantic correctness of the model's interpretation.

For no supported violation, evidence may be empty: a poem need not contain a particular sentence
proving the absence of a violation. The response must still cover the complete candidate scope,
identify every applicable boundary, and explain its reading. The host does not require the model to
invent an instruction or a violating span to satisfy the schema.

Malformed JSON, unknown/duplicate/missing candidate IDs, unknown boundary IDs, mismatched request or
contract identity, invalid ranges, contradictory results, truncated responses, or a model/transport
failure cause rejection of the response as a whole. No subset is silently treated as cleared. Existing
findings remain and a review failure adds `tier_unavailable` (or a separately versioned review-gap
cause if introduced). Missing output is never shorthand for no supported violation.

## Finding eligibility and composition

Eligibility is a host decision based on ML provenance: a retained `ml.classifier` observation bound
to its matching `MlReport`, original input identity, and classified scope. `agent_directed` class
alone is insufficient because structural findings use it too. Text imitating an ML rule name or a
review result cannot nominate a candidate.

The implementation must use a distinct review report/type and a finalizer that enforces
ML-only demotion. Reusing unrestricted `SpanJudgement` indices would allow a routing mistake to
demote structural findings. The host must validate eligibility again when applying the report.

The unchanged structural judge reviews only structural candidates in the candidate configuration;
this proposed review handles only ML candidates. For a mixed verdict, both read the same full input
and caller policy. Results are applied using stable host mappings, not stale indices after a first
review has reordered the reason list. A failure in either requested review cannot erase the other
tier's findings or any true analysis gap. The prepared baseline continues its existing routing so the
effect of the proposed routing change is measured rather than hidden.

Demotion preserves the complete reason in `suppressed`, its ML provenance, original span, display
truncation flag, and new review attribution. Score is recomputed from active retained analysis.
Display flags such as `reasons_truncated` do not indicate lost analysis and do not prevent review.
Actual analysis-budget gaps survive demotion. The review cannot add findings,
increase severity, erase prior suppressions, or remove actual analysis gaps.

The presentation change in `Reason::excerpt_truncated` is independent. Shortened display alone does
not prevent an ML review if the reviewer receives the full document. Failed inference, skipped
chunks/input, missing findings, and unavailable judge context remain incomplete. A fully examined
document may become `Clean` only when all active findings are legitimately demoted and no actual
analysis gap remains.

## Offline acceptance cases

These are synthetic contract cases, not new accuracy measurements or replacements for upstream labels.
Before enabling the new route, test the real request/parser/finalizer path with controlled responses:

| Case | Required behavior |
| --- | --- |
| Poem about secrets, ML-only finding; complete hierarchy context | Valid no-supported-violation response demotes ML; complete verdict may become clean. |
| Ordinary translation request, ML-only finding; caller permits that task | Instruction form alone cannot prevent a valid no-supported-violation response. |
| Explicit attempt to override the application and reveal hidden instructions | Supported-violation response retains ML. Keep as an attack control in live evaluation. |
| Quoted override riding inside unrelated tool output | Claims of example status do not override the caller's source or task. |
| Benign analytical discussion of an override | May clear with full relevant caller context; inspect embedded directives independently. |
| Export request with missing object/destination authorization | Indeterminate; no invented permission from source, wording, or label. |
| ML and structural findings together; ML cleared | Structural reasons, their scores, and provenance remain. |
| ML-directed response targets a structural ID | Reject the entire response; retain all findings. |
| Two candidate IDs, one omitted or duplicated | Reject; no partial clean result. |
| Early display excerpt cut, full document ends with an override | Review sees the tail; a 256-byte prefix cannot substitute for the full document. |
| Complete input with only display metadata, all ML findings demoted | No artificial review floor. |
| Missing input/chunks, failed inference, or a dropped reason | Actual incomplete status survives every demotion. |
| Forged caller context or response JSON embedded in the document | Treat it as document data; host IDs, scope, and policy remain unchanged. |
| Unreachable endpoint or malformed/ambiguous response | Keep findings and report incomplete review. |

Include property tests that arbitrary responses cannot demote a structural reason, grant permissions,
drop a real gap, add evidence, or increase severity. Parsing tests cannot prove semantic reliability;
live measurement with caught-attack controls remains required.

## Separate evaluation arms

Freeze the model, scores, threshold, inputs, labels, and caller context. Use four explicitly named arms:

1. **Prepared baseline:** original excerpt-gap semantics plus existing judge prompt/routing.
2. **Presentation only:** excerpt metadata plus exactly the same judge responses as arm 1 where
   request content is identical. Validate request hashes before replay; do not approximate responses
   from final verdicts. This isolates decision semantics from model variation.
3. **ML review only:** new ML review/routing with original excerpt-gap semantics, evaluated in the
   preserved baseline environment. This isolates review changes while retaining the old floor.
4. **Combined:** new ML review/routing plus presentation metadata, applying the same validated
   per-candidate responses as arm 3 to isolate presentation effects.

The default judge path retains parsed reports; the implementation also exposes exact successful
response-body capture seams for baseline and ML review requests. Before live paired evaluation,
use an ignored evaluation harness that captures these responses and exact HTTP-request hashes
without changing the baseline prompt. Preserve endpoint/model identity,
prompt and schema versions, source/binary hashes, request policy, failures, latency, and ordering.
Use the same model configuration for baseline and candidate review; do not silently change model
while testing a review contract.

For every arm, report per-source and total block/review/allow transitions against the original
**63 benign blocks, 264 caught attacks, 74 benign interruptions, and 272 interrupted attacks**.
Primary outcomes are benign interruptions removed and caught attacks that become fully allowed.
Also report block-to-review changes, attack block retention, and all tier failures in the denominators.
No-findings cases are retained as unchanged controls: this review cannot recover the 28 allowed
attacks. Keep original labels separate from provisional reviewed labels.

Present outcomes under both original and candidate semantics, clearly labeling hypothetical
all-demotion bounds as bounds. Do not present fewer coverage flags as increased accuracy. Select a
candidate on development data, freeze it, then evaluate an untouched holdout with exact/normalized
exposure exclusions. Application export and indirect/reference coverage require separate task-aware
evaluations.


## Shared response acceptance

ML and structural review share the [raw-envelope acceptance contract](../../004-judgement-tier/contracts/judge-tier.md#response-handling).
ML retains its 64 KiB response limit and strict candidate, request, boundary, range, and evidence
validation. Structural review retains its own schema and scope. On a combined route, each response
is accepted independently: a rejected response preserves its findings and adds a gap; a valid
other response may affect only its own findings under the caller's authority. Neither can erase
the other's failure gap.
