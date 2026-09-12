# Contract: rule set format

**Feature**: `001-structural-detection-cli`

Rules are declarative TOML — the form required by constitution Principle III, and the artifact a
reviewer reads in a pull request to understand what the scanner does. TOML because it carries
comments (a rule's justification lives beside it), diffs cleanly line-by-line, and matches the
policy format bee already uses, so a contributor moving between the repositories reads one syntax.

---

## Document shape

```toml
[ruleset]
name = "please.builtin"
version = "0.1.0"

# Score-to-band mapping. Data, not code, so a deployment retunes without a rebuild.
[bands]
low = 20
medium = 45
high = 70
critical = 90

[[rule]]
id = "override.ignore_previous"
class = "override"
severity = 85
literals = ["ignore", "disregard", "forget"]
pattern = '(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|prior|above|earlier|all)\b[^.\n]{0,20}\b(instruction|prompt|rule|direction)s?\b'
fires_in_quotes = false
description = "Instruction directed at a reading agent to disregard prior instructions."

[[rule]]
id = "solicitation.system_prompt"
class = "solicitation"
severity = 70
literals = ["system prompt", "your instructions", "initial prompt"]
pattern = '(?i)\b(reveal|repeat|print|show|output|display)\b[^.\n]{0,30}\b(system prompt|your instructions|initial prompt)\b'
description = "Request for the agent's own instructions or configuration."
```

---

## `[ruleset]`

| Key | Required | Notes |
|---|---|---|
| `name` | yes | Namespace, e.g. `please.builtin`, `acme.internal` |
| `version` | yes | Semantic version; recorded in every verdict |

`name` and `version`, plus a digest over the resolved content, form the `ruleset` field of every
verdict — which is what makes a verdict from six months ago attributable to exact rules (SC-012).

## `[bands]`

Lower bound of each band, ascending. A score below `low` bands as `none`. Boundaries here are
**provisional** and will be recalibrated against per-source corpus metrics when the evaluation
harness lands; they are not currently derived from measurement, and the tool's documentation says so
rather than implying a calibration that has not happened.

## `[[rule]]`

| Key | Required | Default | Notes |
|---|---|---|---|
| `id` | yes | | `^[a-z0-9_]+(\.[a-z0-9_]+)+$`; unique within the resolved set |
| `class` | yes | | One of the six detection classes |
| `severity` | yes | | `0..=100`, contribution before aggregation |
| `literals` | no | `[]` | Prefilter gate; see below |
| `pattern` | yes | | Linear-time syntax only |
| `fires_in_quotes` | no | `false` | Whether the rule survives the quoting pre-pass |
| `enabled` | no | `true` | |
| `description` | yes | | Shown in output, so a finding explains itself |

`description` is required rather than optional on purpose: an unexplained finding is one a user
cannot act on, and it is the first thing that erodes trust in a scanner's output.

### `literals` and why they matter

Literals are the cheap gate. All literals from all rules are compiled into one multi-pattern
automaton; a rule's `pattern` is only compiled and evaluated if one of its literals is present. Text
matching no literal costs one linear pass over the input and compiles nothing.

A rule with an empty `literals` list is evaluated against every input. That is permitted but
discouraged, and the loader emits a warning naming the rule, because a handful of such rules
reintroduces the eager-compilation cost the design exists to avoid.

### `pattern` constraints

Patterns are matched by a finite-automaton engine. Look-around and backreferences are **not
expressible** — a pattern using them fails to compile and therefore fails to load. This is the
enforcement mechanism for the constitution's linear-time requirement: a rule author cannot write a
catastrophically backtracking pattern, because the syntax has no way to say it. The guarantee is
structural rather than a review convention.

---

## Load-time validation

A rule set is accepted whole or rejected whole. Partial loading is never permitted — a half-loaded
rule set is indistinguishable from a deliberately weakened one, and would silently reduce coverage.

Rejected, with a diagnostic naming the offending rule:

| Condition | Why |
|---|---|
| Unknown or malformed key | Typos silently disabling a rule are worse than a hard failure |
| `id` malformed or duplicated | Identity is the suppression handle and must be unambiguous |
| `class` not recognised | Prevents a rule that can never be reported on |
| `severity` or band outside `0..=100` | |
| `pattern` fails to compile | Includes any use of look-around or backreferences |
| `pattern` source exceeds the length limit | Bounds the compiled program |
| Compiled pattern exceeds the program-size limit | A short pattern can expand enormously; see below |
| Rule count exceeds the per-set limit | |

### Resource limits are a security control, not tidiness

A caller may supply their own rules (FR-023), so a rule set is untrusted input to the scanner. The
pattern `a{5}{5}{5}{5}{5}{5}` is twenty characters of source that expands to `a{15625}` and an
automaton to match. Without a compiled-size limit, a rule set copied from an untrusted source is a
memory-exhaustion path into the tool whose job is to prevent exactly that class of thing.

Limits are enforced at compile time, per rule, with a documented default.

---

## Resolution and suppression

```text
built-in default  →  caller additions (--rules)  →  caller suppressions (--disable-rule)
```

- An addition whose `id` matches a built-in **replaces** it. Replacement is reported at load, so
  overriding a rule is never accidental.
- Suppression is by `id` and takes effect last, so a rule can be added by one layer and suppressed
  by another.
- Suppressing an unknown `id` is a usage error, not a silent no-op — the common cause is a typo, and
  a typo that quietly leaves a rule enabled defeats the purpose of disabling it.

The resolved set's digest covers every rule that survived resolution, so the verdict's `ruleset`
field describes what actually ran rather than what was requested.

---

## Frame-anchored matching

Rules declaring `anchor = "frame"` are eligible only when their match starts at a semantic-unit
boundary in the searched bytes. Both matcher operations enforce this before returning results:
`Matcher::find` returns eligible occurrences and `Matcher::matching_rules` returns each eligible
rule once. Raw regex occurrences count toward the match cap before frame filtering; an exhausted
cap remains a coverage gap even if all retained hits are off-frame.

Decoded buffers use their own frame coordinates. Original encoded-region spans are attached only
when observations are constructed. Quoting suppression is separate and follows eligibility;
turning it off cannot restore an off-frame occurrence. Frame syntax and quoting semantics are
unchanged by this consolidation.

For low-level Rust callers, `detect::apply_frame` and `Matcher::is_frame_anchored` are removed.
Consume the frame-aware matcher results directly, then apply quoting suppression where appropriate.
The placement decision is recorded in [005 D2's amendment](../../005-agentic-surface/plan.md#d2-amendment--frame-eligibility-ownership-2026-09-12).

---

## Shared file acquisition

The CLI and evaluation harness use `please_scan::load_engine(files, disabled)` to acquire rule sets.
It reads and parses files in the supplied order, then delegates one layered build to core. Core
preparation remains filesystem-free. No engine is returned if any file fails or preparation rejects
the resolved set; evaluation rejects invalid rules before creating an evaluation run.

`RuleLoadError` distinguishes default built-in loading, file reads, file parsing, and final preparation.
Read and parse errors retain the supplied path and underlying error. Preparation errors retain core's
rule IDs where available, without inventing a file attribution for a whole-set failure. The CLI owns
presentation: default built-in failures exit 70, caller selection failures exit 64, and replacement
warnings go to stderr. Evaluation retains its selection description and reports the same attributed
acquisition errors.

This consolidation preserves resolution order, suppression behavior, base calibration, provenance,
and compiled validation. It adds no production dependencies or storage interface.

---

## Worked example: a team suppresses a rule and adds their own

Satisfies SC-010. No rebuild, no reinstall.

```toml
# acme-rules.toml
[ruleset]
name = "acme.internal"
version = "1.0.0"

[[rule]]
id = "boundary.acme_tool_marker"
class = "boundary"
severity = 75
literals = ["<<<ACME_TOOL"]
pattern = '<<<ACME_TOOL[A-Z_]*>>>'
description = "Forged internal tool-result delimiter used by our agent framework."
```

```sh
plz scan --rules acme-rules.toml --disable-rule override.ignore_previous ./skills
```
