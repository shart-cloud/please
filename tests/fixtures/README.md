# Fixtures

Labelled test cases for the detection engine. These are the only accuracy evidence Feature 001 has —
corpus-scale metrics arrive with `please-eval` — so what is here, and what is missing from here, is what
the tool's claims rest on.

**No corpus text is vendored.** The primary evaluation corpus aggregates 41 sources that retain their
own licences (constitution Principle IV). Everything in this tree is authored for this project or drawn
from permissively-licensed material.

## Layout

```text
tests/fixtures/
├── *.jsonl          labelled text cases — the bulk of the corpus
├── files/           fixtures where being a real file matters (binaries, certificates)
├── adversarial/     pathological inputs: cycles, deep nesting, invalid UTF-8, huge lines
└── rules/           rule sets: valid, malformed, and resource-exhausting
```

The split is about whether *fileness* is part of the test. A case that is just text belongs in JSONL,
where it carries its labels with it. A case that has to be an actual file on disk — invalid UTF-8 that
no JSON string can hold, a certificate, a rule set the loader must open, a directory the walker must
traverse — belongs in a directory.

## Case format (`*.jsonl`)

One JSON object per line. Newline-delimited rather than a single array so that files append cleanly,
diff per-case, and can be filtered with ordinary line tools.

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique across all files, e.g. `indirect-email-002`. Stable: it is how a regression is referred to |
| `text` | yes | The content to scan, verbatim |
| `category` | yes | `benign` \| `indirect_injection` \| `direct_injection` |
| `context` | yes | Where this text would reach an agent — see below |
| `subcategory` | yes | The specific scenario, e.g. `instruction_after_whitespace` |
| `expected` | yes | `benign` \| `injection` |
| `difficulty` | yes | `easy` \| `medium` \| `hard` |
| `notes` | yes | Why this case exists and what it is probing |
| `expected_classes` | no | Detection classes that should fire, e.g. `["override"]`. Enables per-class assertions (SC-002); absent means "any class is acceptable" |

### `context` — the attack vector

This field is the reason the format is worth more than a directory of files. It records **where hostile
text would actually arrive**, which is the dimension the product is aimed at and the one public data
cannot measure: agentic sources are about 0.45% of the primary corpus's adversarial rows.

| Value | Vector |
|---|---|
| `email_body` | Text in a message an agent summarises or acts on |
| `tool_result` | Output returned to an agent by a tool it called |
| `skill_md` | A skill or instruction file the harness loads |
| `mcp_tool_description` | A tool description advertised by a remote server |
| `file_read` | File contents an agent reads |
| `repo_config` | Agent-readable configuration in a repository — `.cursorrules`, `.github/copilot-instructions.md` |
| `manifest` | A package manifest an agent parses — `package.json`, `pyproject.toml` |
| `issue_body` | A GitHub issue or pull-request body an agent is asked to analyse |

The last three were added with `handcrafted-repo-config.jsonl`. They are the repository and protocol
delivery vectors catalogued in arXiv:2601.17548 (D2.1, D2.2), and they had **zero** coverage before —
which mattered, because they are path-dense and the built-in rules' `[^.\n]{0,N}` gap bound cannot cross
a period. A defect our whole corpus was blind to was a defect in the corpus, not only in the rule.

Metrics are reported per `context`, so a strong result on email cannot conceal a weak one on tool
results.

### `expected` and `notes` carry the argument

`expected` is the assertion. `notes` is why anyone should agree with it — and for the hard benign cases
that is doing real work. `benign-security-prose-002` is a CVE advisory that quotes an override payload
as an example; it is labelled benign, and the note is what makes that defensible rather than arbitrary.

Every case needs a note. A fixture nobody can justify is a fixture nobody can safely change later.

## What the benign set is for

The benign cases are the more valuable half, and the harder half to build.

Positives are easy to write and easy to detect. The negatives that decide whether a firewall stays
switched on are documents that *discuss* injection without being injection: threat models, CVE
writeups, security tooling documentation, a colleague's email about test results, this repository's own
specification. Those contain attack strings as subject matter. A detector that flags them is unusable
by exactly the people most likely to evaluate it.

**SC-003 requires at least 200 benign cases**, at most 1% of which may produce a finding. The minimum is
part of the criterion, not a suggestion: a 1% rate over 20 cases silently means zero, which is a much
stricter bar than intended and cannot be met honestly. `crates/core/tests/fixtures.rs` fails the run if
the set is short, so this cannot be quietly satisfied.

Current count is far below that. It is the single largest outstanding piece of work in Feature 001.

## Current inventory

| File | Cases | Purpose |
|---|---|---|
| `handcrafted-benign.jsonl` | 17 | Hard negatives — security prose, CVE writeups, legitimate override language |
| `handcrafted-indirect.jsonl` | 19 | Indirect injection across email, tool result, skill file, MCP tool description |
| `handcrafted-repo-config.jsonl` | 13 | Repository and protocol delivery vectors, and the sentence-bound cases |
| `handcrafted-override.jsonl` | 3 | Direct override phrasing |
| `handcrafted-boundary.jsonl` | 3 | Forged role markers, tool results, delimiters |
| `handcrafted-solicitation.jsonl` | 3 | System-prompt and credential extraction |
| `handcrafted-concealment.jsonl` | 5 | Zero-width, tag-block, variation selectors, HTML comments |
| `handcrafted-confusable.jsonl` | 2 | Homoglyph substitution |
| `handcrafted-encoding.jsonl` | 6 | Base-64, hex, ROT-13, reversal, leetspeak |

Counts are checked by test rather than trusted from this table. This one had drifted — it claimed 12
benign cases against 17 and omitted six files entirely — which is the failure mode `docs/limits.md`
describes at length under "`plz` could not load a caller's rule set": prose that was accurate when
written and quietly stopped being so, because prose does not fail.

`handcrafted-repo-config.jsonl` carries two things beyond its delivery vectors, and both are worth
knowing before editing it:

* **Matched pairs.** `solicitation-credentials-path-001` and `-nopath-001` are the same payload with and
  without a real filesystem path. The pair is the evidence for the sentence-bound change in
  `rules/builtin.toml`; separating them destroys it.
* **Regression guards.** `override-separator-punctuation-001` and `-002` are `IGNORE!PREVIOUS!INSTRUCTIONS`
  and its `?` variant, real LLMail-Inject evasions. They are detected today and must stay detected — they
  are what fails if someone "corrects" the gap bound to exclude `!` and `?`. See
  `crates/core/tests/sentence_bound.rs`.

## Adding cases

1. Pick the file by `category`; create a new `handcrafted-<category>.jsonl` if none fits.
2. Give it an `id` that reads as what it is, and never reuse one.
3. Write the `notes` first. If the justification is hard to write, the label is probably wrong.
4. Prefer `hard` cases. An easy case that every approach catches proves little; the discriminating
   cases are where a detector earns trust.
5. For a benign case, ask what would make a naive detector fire. If nothing would, it is not pulling
   its weight as a negative.
