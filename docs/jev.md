# TypeSafe Jev contextual advice

`plz jev` is an opt-in advisory command, available with the existing `judge` build feature. It uses TypeSafe's [documented HTTP API](https://docs.typesafe.ai/api). It does not modify a scan verdict, suppress findings, grant release authority, or run during `plz scan`. The core and the no-default-features build remain network-free.

`plz clap` is an alias for `plz jev` (please clap). Both commands accept the same arguments; for example, `plz clap --check`.


## Interactive workspace

Run `plz clap` in a terminal to open the Jev workspace. `plz jev` is identical. You can also request the UI explicitly:

```bash
plz clap --tui
plz clap --tui candidate.txt --context docs/jev-context.example.json --provenance caller-provided
```

Paste text into the input field, or press F2 on an empty input field to switch to a file path. Enter the caller's task, the resource or scope the boundary covers, and the allowed / forbidden actions. Choose the input source with Space or the arrow keys. The form constructs one caller-owned tool-action boundary; use `--context` for multiple boundaries or other boundary kinds. Loaded context is displayed read-only and submitted unchanged.

Paste an API key into the masked key field, or configure `TYPESAFE_API_KEY` before launch. The key is held in memory for the session and never saved with advice. No setup script, evaluator binary, Python environment or experiment cache is required.

- Tab / Shift+Tab moves between fields.
- F2 switches text/file mode after clearing the input field with Ctrl+U.
- F3 previews the exact request locally without contacting TypeSafe.
- F5 / Ctrl+R submits one request. Input is locked while it runs; there are no automatic retries.
- Ctrl+S writes the displayed advice as JSON to the save path. Existing files are never overwritten; Unix output files are created with mode 0600.
- F6 saves a named caller-context preset: enter a new path, Tab to edit its name, then Enter.
- F7 loads a caller-context preset from an explicitly chosen file.
- F8 opens saved advice read-only; F4 returns to the assessment form.
- In file dialogs, Esc cancels and Ctrl+U clears the current path/name field.
- PgUp / PgDn scrolls the preview or result.
- Esc / Ctrl+C closes the UI. Closing during a request stops waiting locally; a request already sent may still be processed by the provider.

Use a terminal at least 90 columns by 30 rows. Candidate text and displayed metadata are escaped for terminal control characters without changing the bytes submitted. Pasted input over the field cap is rejected in full, and oversized or non-UTF-8 files are refused. Results show the final advisory relation, native choice, provider probabilities/confidence, model, token usage and identities. Editing assessment fields clears the old displayed result.

The TUI uses the existing four-way advisory recipe and strict thresholds. It does not promote one of the research recipes or alter scan enforcement. The workflow is a supported CLI feature; the model's measured limitations still apply.

The default build includes the optional `tui` feature, which implies `judge`. Build with `--no-default-features --features judge` for JSON-only Jev, or `--no-default-features` for the offline scanner without Jev or terminal dependencies. The UI uses Ratatui 0.29 and Crossterm 0.28; the lockfile pins their dependency chain.

With explicit input/context arguments, the command continues to emit JSON unless `--tui` is supplied. Bare invocation with redirected streams remains a usage error and never starts a request. The UI exits with the most recent assessment's status (1 conflict, 2 indeterminate/error, 3 aligned/material); closing before any assessment returns 0.

## Reusable context and offline saved advice

    plz clap --preset my-review-context.json
    plz clap --tui candidate.txt --preset my-review-context.json
    plz clap --view-advice jev-advice-previous.json

Presets use schema please-jev-context/v1 with fields schema_version, name,
context (the full CallerContext), and provenance. Saving requires no candidate
or credential. No session history, candidate text or key is automatically saved.
Both preset and advice saves create new files, refuse overwrite, and use Unix
mode 0600. Known in-memory/environment credentials accidentally placed in
exported fields are rejected before writing.

Loading replaces task, boundaries and provenance, clears displayed advice and
leaves candidate input and the masked key unchanged. Imported context stays
read-only and preserves all boundary kinds and completeness fields. Valid
unavailable scopes round-trip but still prevent requests when incomplete;
contradictory completeness metadata is rejected. Edit complex caller-owned JSON
externally and reload it. --preset opens the TUI and conflicts with --context
and --provenance. No preset directory or automatic persistence is created.

The F8 / --view-advice viewer is offline and marked historical. It does not
assess the current form, read candidate files, or use credentials. It displays
input/context/request/recipe identities, requested/returned models and native
scores. These are unverified file claims, not signatures. Opening saved advice
does not change the latest assessment exit status; a standalone viewer exits 0
and invalid startup files exit 2. F4 returns to the form, where F5 explicitly
requests another assessment.

Saved advice must match the existing please-jev-advisory/v1 schema and its
four-way gates. Unknown, duplicate, missing and inconsistent fields, invalid
identifiers, invalid score distributions and nonempty evidence are refused.
Local files are capped at 128 KiB including JSON escaping/indentation; preset
context keeps its 16 KiB limit. Terminal controls are escaped. File dialogs and
the viewer work below the assessment form's 90x30 minimum.

## Configure and inspect

Get an API key from the TypeSafe console. In your WSL terminal, enter it without placing the value in shell history:

```bash
read -rsp 'TypeSafe API key: ' TYPESAFE_API_KEY
export TYPESAFE_API_KEY
plz jev --check
```

In JSON mode, the key is read from `TYPESAFE_API_KEY`. The TUI can also accept a masked in-memory key; Anthropic credentials are never reused. The endpoint is fixed to `https://api.typesafe.ai/v1/systemone`; redirects are refused. `--check` makes no request and reports only whether a credential is configured. Set `TYPESAFE_MODEL` or pass `--model` to select a model; the default is `jev-latest`. This alias does not pin a weight revision. Requested and returned model identifiers are both recorded.

## Caller context and invocation

Use the same caller-owned `CallerContext` schema as the existing boundary reviewer: task, typed boundaries, and explicit relevant/known/unavailable scope lists. [Example context](jev-context.example.json) authorizes reading a file while prohibiting changes. The caller must decide which scopes are relevant; never derive permissions from candidate text.

Inspect the exact request locally:

```bash
plz jev candidate.txt --context docs/jev-context.example.json --provenance user-input --request-only
```

Then request advice:

```bash
plz jev candidate.txt --context docs/jev-context.example.json --provenance user-input
```

Only the explicit Jev invocation sends the candidate and caller context to TypeSafe. Use `-` for candidate text on standard input. Context must be complete and include a nonempty task; missing or contradictory scope is refused before networking. Candidate and context each have a 16 KiB limit, the encoded request has a 64 KiB limit, and the response has a 16 KiB limit. Inputs are never silently shortened. The remote provider's internal context handling is not independently verified.

## Output and exit status

JSON contains the four-way advisory relation, native choice, full returned distribution, provider confidence, usage, requested/returned model IDs, input/context/request/response/recipe identities, and empty evidence. No model-written spans are invented. Provider probabilities are not claimed to be calibrated for Please.

The initial uncalibrated decoder requires top support >=0.7, margin >=0.15 and confidence >=0.5; otherwise it abstains. Invalid/missing/duplicate fields, non-finite/out-of-range scores, a distribution not summing to one, and a choice inconsistent with its distribution are rejected.

- 1: advisory conflict.
- 2: indeterminate, incomplete context, missing credentials, transport failure, or invalid response.
- 3: aligned or non-operative advice, **not a clean scan verdict**.
- 0: successful `--check` or `--request-only`.
- 64: CLI usage error.

A completed Jev assessment never exits 0. Ordinary `plz scan` behavior and exit codes are unchanged. Requests have a 30-second deadline and no automatic retries, so a rate limit, overload, or authentication failure remains visible instead of consuming more requests. Error bodies and credentials are not included in diagnostics.

## Evidence boundary

Offline tests cover request identity, malformed/duplicate JSON, context completeness, raw score preservation, arbitrary provider text, local HTTP success, authentication failures, redirects, response caps, deadlines and CLI behavior. These are integration contracts, not a Jev accuracy measurement. The initial implementation was validated offline. A later user-authorized [live comparison](research/jev-comparison-2026-09-16.md) evaluated 1,950 exposed cases. Independent labels and a fresh holdout remain required before considering deeper integration.

This command is separate from the failed G1/N1/N2 local-model experiment. Adding Jev does not revise those results or establish that Jev passes their gates.

Implementation validation: nine Jev request/parser/property contracts, four local HTTP transport tests, three Jev CLI tests, the no-default-features CLI suite, the full workspace credential-canary gate, Clippy, and core/dependency/ML/WebAssembly isolation checks passed. The installed release passed three ordinary-scan byte-for-byte comparisons against the saved prior release.

The live comparison used the existing thresholds unchanged. Jev improved aggregate contextual recall over the local recipes but failed analysis-only and missing-context cases; no operating point passed calibration. Artifact detection was evaluated separately with a benchmark-only prompt, not the contextual CLI command. See the linked report for source-level results and response-validation failures.

A subsequent [controlled contextual follow-up](research/jev-context-followup-result-2026-09-16.md) tested clearer context, focused questions and additional caller facts. Focused questions improved analysis recognition and missing-permission abstention but reduced conflict recall and coverage. No variant passed the frozen screening gates; the installed recipe remains unchanged.

A further [usage-pattern experiment](research/jev-usage-result-2026-09-16.md) compared rewritten questions, caller-directed routing, contrastive examples and component-scoped validation on 204 cases. Concise caller routing improved the original slice from 65.6% to 85.6% macro recall and detected all 69 full-screen conflicts, but analysis-only recall and coverage still missed the frozen gates. No variant advanced; the installed recipe remains unchanged.

Interactive release validation: eleven UI contracts, six default-feature CLI contracts, the existing Jev parser suite and five local HTTP transport tests passed alongside the full workspace credential-canary gate and Clippy. Offline and JSON-only configurations, core/dependency isolation and the WebAssembly build passed. Terminal layouts were inspected at 90x30 and 120x40. Actual PTY tests covered bare-command launch, field entry, preview, missing-key handling, a single successful synthetic live request, JSON export, key masking and terminal restoration. Ordinary scanner output/exit status matched the prior installed binary on three fixtures.

Local-file continuation validation (2026-09-17): 15 UI contracts, 12 Jev
parser/request/property contracts and 7 default Jev CLI contracts passed.
The full workspace credential-canary suite, Clippy, formatting, offline/JSON-only
configurations, core/dependency/WebAssembly checks and release build passed.
Actual terminal checks covered preset save/load and reopening earlier advice;
viewer startup also passed at 60x20. Three scanner fixture outputs and the exact
Jev request matched the prior installed binary. The release was installed with
the previous executable retained. No new provider request was made. See the
[completion report](research/jev-local-files-result-2026-09-17.md) and
[independent review packet](research/jev-review-packet-2026-09-17/README.md).
