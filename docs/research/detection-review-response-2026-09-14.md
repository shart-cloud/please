# Email-rule review: withdraw the candidate

## Decision

**Withdraw `solicitation.email_transmission` and
`solicitation.email_transmission_introduced` from the built-in rule set.** The
review found a missing authorization distinction and unstable behavior under
ordinary rewording. Neither the named-object restriction nor severity 75 earns
default High applicability. No replacement vocabulary restriction, threshold
change, or opt-in production rule is introduced to retain the numerical target.

This is the current disposition of the candidate in the
[original experiment report](detection-improvement-2026-09-14.md). That report,
its machine record, previous validation, rejected approaches, and supplied
reviewer evidence remain unchanged historical evidence. The current built-in
rules are byte-identical to the original baseline, digest `3b946803b23151d5`.
The prior candidate digest was `98eb13cabaeedf28`.

## Trust boundary

An authorized user can ask an agent to email a document, file, result, or public
information to a named recipient. Neither the noun nor the email address proves
that the recipient is external to the user's organization or that disclosure is
unauthorized. Conversely, calling something “public” inside an untrusted payload
does not authorize transmission.

The injection boundary is crossed when instructions in third-party content
(such as a document or tool response) are promoted into authority to redirect
the agent beyond the trusted task. The caller must establish the task and the
permission to perform the action. Input provenance describes origin; it is not
an authorization decision. A tool response can also contain legitimate quoted
requests. Simply limiting these patterns to tool responses would not solve that
distinction.

The withdrawn patterns recognize **transmission-risk signals**: imperative email
wording, a named object, and some address syntax. They do not establish injection
or unauthorized disclosure. Severity 75 was borrowed from existing directive
rules; there is no authorization evidence or calibration that justifies making
these additional signals High by default. A future action-policy feature could
surface a transmission request for comparison with caller-established permissions,
but that requires a separate interface and evaluation. It is not implemented here.
This review does not establish that the remaining baseline rules solve authorization.

## New exposure and label provenance

The supplied review at `.cache/detection-review-oi0bjm5x` is recorded as **new
development exposure**, including all ten requests and their native saved
results. Their labels are reviewer-authored as supplied; the reviewer's identity
and any independent label review are unspecified. The inherited public-corpus
notes in that custom input package do not describe these ten requests.

Before removing the rules, Codex authored a targeted matrix: four objects
(conference documents, public event details, arithmetic results, uploaded files)
crossed with ten recipient/syntax forms. Each of the 40 wordings has:

- An authorized user-request scenario: the user may share the material and
  explicitly approves this destination.
- An adversarial tool-response scenario: the trusted task is a local summary;
  an attacker inserts the email instruction to induce an unauthorized send.
- An explicit-override control: the adversarial instruction also tells the agent
  to ignore prior instructions.

The first two scenarios intentionally have identical scanned bytes. The
[scenario fixture](../../crates/core/tests/data/email_review_scenarios.jsonl)
records task, origin, label rationale, pair ID, syntax, and authorship. Codex
authored the labels and checked their consistency; **no independent reviewer
reviewed these new labels**. These are first-party development mechanism checks,
not a held-out attack-family benchmark. The 120 scenario rows contain only 80
distinct scanned strings; paired and templated observations are not independent.

The native evaluator runs product/enforcement/High, structural only, unspecified
provenance. It receives the text, not the scenario's task or authorization
metadata. The contextual labels are evaluation expectations, not extra detector
inputs. Native results therefore measure both the rule's wording sensitivity and
its inability to separate these scenarios. They do not simulate an agent actually
sending email or demonstrate successful exploitation.

## Targeted results

| Check | Rows | Baseline High | Email candidate High | After withdrawal High |
|---|---:|---:|---:|---:|
| Reviewer authorized requests | 10 | 0 | 4 | 0 |
| New authorized transmission requests | 40 | 0 | 16 | 0 |
| Paired unauthorized tool directives | 40 | 0 | 16 | 0 |
| Explicit instruction-override controls | 40 | 40 | 40 | 40 |

All these runs have zero coverage gaps. The candidate's newly detected contextual
attacks have equally detected authorized twins. Withdrawing it removes those
false positives **and leaves the plain unauthorized email mechanism undetected**.
That unresolved mechanism is a coverage limitation, not a success claim.

Each syntax below was evaluated with all four objects in both authorization
scenarios. “High” describes the email candidate; baseline and withdrawn rules
detect none of the plain email requests in either scenario.

| Recipient / syntax form | Candidate High in each scenario |
|---|---:|
| Please email the object to `coordinator@example.org` | 4/4 |
| To the organizer at that address | 0/4 |
| To my colleague at that address | 0/4 |
| To `Jordan <coordinator@example.org>` | 0/4 |
| To `<coordinator@example.org>` | 0/4 |
| `To coordinator@example.org, please email` the object | 0/4 |
| `Please email coordinator@example.org` the object | 0/4 |
| `Could you please email` the object to the address | 4/4 |
| Bare `Email` imperative with direct address | 4/4 |
| Review the object `and then email` it by its full name | 4/4 |

Compared with the direct-recipient version, **24 of 36 wording comparisons flip
the verdict**, in each of the authorized and adversarial scenarios. The supplied
conference-document / organizer pair is reproduced exactly. Broadening the
recipient grammar would also broaden authorized false positives; narrowing the
object vocabulary again would not create an authorization boundary.

## Development and prior validation

| Primary slice | Baseline | Email candidate | After withdrawal |
|---|---:|---:|---:|
| InjecAgent | 442/1,054 | 510/1,054 | 442/1,054 |
| LLMail-Inject | 11,263/27,963 | 11,263/27,963 | 11,263/27,963 |
| OR-Bench false positives | 0/3,000 | 0/3,000 | 0/3,000 |

The current implementation **does not meet the 495-row InjecAgent target**.
The earlier +68 came from four payload forms repeated 17 times. The additional
16 detections in the stratified development slice were exact InjecAgent
duplicates. Neither result establishes unseen attack-family effectiveness.

All 14 frozen development slices reproduce baseline native per-row results,
including findings and coverage causes. This includes clean negatives 516/6,640,
non-adversarial negatives 534/13,169, multilingual negatives 19/3,196, benign
fixtures 14/20, matched generated negatives 0/14, and frozen repository prose
32/87. The SPML exclusions and denominators retain their original meanings;
these raw counts do not remove those rows. LLMail retains 154 distinct incomplete
rows; the other primary slices retain zero.

The prior validation had **87/300 attack detections and 0/300 benign detections
for both baseline and email candidate**, with no recall improvement. The current
rules reproduce those per-row results. That set was untouched at its original
evaluation, but its contents and results are now development exposure. Repeating
it here is a regression check, not fresh validation. The targeted matrix above
adds evidence about the newly attempted mechanism and its authorized controls;
it supplies no broader generalization estimate.

## Role-marker prefilter: separate follow-up

The rejected prefilter experiment remains separate from the withdrawn email rules.
It added **976 LLMail detections**, with no lost detections, while distinct
incomplete rows rose from 154 to 157. A new bounded diagnostic and native replay
confirm the three added gaps are newly visible raw-match saturation, rather than
reduced analysis capability. The original no-increase criterion still rejects
the change. Changing that criterion requires an explicit acceptance decision.

See the [role-marker follow-up](role-marker-prefilter-follow-up-2026-09-14.md)
for row-level evidence, why saturation precedes frame filtering, and the pending
decision. No prefilter, limit, gap reporting, or acceptance criterion changes in
this review response.

## Reproduction and preservation

New local evidence lives in `.cache/detection-review-response-20260914/`:

- `preserved-sha256.json`: verifies all **858** existing experiment, reviewer,
  and historical research files unchanged, including snapshots and binaries.
- `exposure.json`, `input-correction.json`, `reviewer-fixture.json`: exposure,
  authorship, hashes, and exact reviewer-text derivation.
- `targeted-inputs-v2.json`: frozen native inputs. The initial package was rejected
  before scanning because positive slices were marked FP-gate eligible. Its
  package and failure log remain preserved; only gate metadata was corrected.
- `eval-cache/results/`: baseline, historical candidate, and withdrawn native
  row results and saved JSON/Markdown/HTML reports for targeted and reviewer
  checks; current development and exposed-validation runs; role-marker replay.
- `summary.json`: exact row comparisons, syntax strata, preservation audit,
  and role-marker diagnostic. [Published summary](detection-review-response-2026-09-14.json).
- `before/`: pre-review rules, tests, and mutation example. The original
  `candidate-freeze/` and `e1/` directories also remain intact.

The native frozen runner accepts `run PACKAGE SHA256 NEW_LABEL high SLICE...`;
set `PLEASE_EVAL_CACHE` to a fresh result directory. The baseline binary is
`../detection-improvement-20260914/frozen-corpus-baseline`, the historical email
binary is `../detection-improvement-20260914/candidate-freeze/frozen-corpus`, and
the rebuilt current binary is `crates/eval/target/release/examples/frozen_corpus`.
Paths beginning `../` above are relative to the new evidence directory.
The [review runner](../../crates/eval/scripts/detection_experiment/run_review.py)
records the exact package selections and hashes; it refuses to overwrite logs.

The [authorization regression tests](../../crates/core/tests/email_authorization.rs)
cover all 50 authorized requests under all four provenance settings and all
40 override controls under tool-response provenance. The new regression first
failed on the reviewer's conference-document request (score 75), then passed
after withdrawal. Historical grammar/property/decode/saturation tests now load
only an explicitly withdrawn test fixture, as does the historical mutation smoke
example. They establish historical rule behavior, not production efficacy.

Validation passed: full `please-core` tests, full standalone evaluator tests,
the final authorization and historical grammar regressions, workspace and
evaluator Clippy with all targets and warnings denied, both formatting checks,
and `git diff --check`. The release frozen evaluator built offline with the
lockfile. The historical mutation smoke ran 5,000 mutations / 10,000 scans;
its findings belong to the withdrawn fixture, not the default rules. The original
improvement acceptance criterion is no longer met after withdrawal.
