# Handoff: Please Jev integration, interactive TUI and next steps

Updated: 2026-09-16
Status: Jev advisory integration and interactive TUI implemented, validated and installed locally. Three live evaluation rounds are preserved. The best research recipe has not passed every gate and is not the recipe used by the TUI.
Next recommended work: reusable caller-context presets and reopening saved advice; in parallel as a separate workstream, independently reviewed analysis/redirection evaluation before promoting caller-routed Jev.

## Current user intent

Jared explored lightweight local models, obtained TypeSafe Jev access, asked for Jev integration, and chose `plz clap` as the CLI alias for `plz jev` (the Jeb Bush joke). The alias is a CLI argument, not a shell alias.

After live comparisons and contextual experiments, Jared clarified that the desired normal TUI is **an interactive tool for assessing his own text or files and displaying Jev's advice**, not the benchmark-results browser. That feature is now implemented. Latest request: recommend what to do next and prepare this handoff. No new task was created, no new development stage was started, and no commit or remote push was made for this handoff.

## Exact workspace and preservation requirements

- WSL distribution: Ubuntu.
- Repository: `/home/jg/git/bee-swarm`.
- Branch: `007-Prompt-Injection-Test-Bench`.
- Observed HEAD: `40f3395c5e681b9b2135b7afa482df9d43a9bab8`.
- Installed binary: `/home/jg/.cargo/bin/plz`.
- Installed SHA-256: `4638e057b1a03be1a5cb1f1900eaf889ee00858dc7a03fa5e72adfecf4eb3a73`.
- Previous installed binary: `/home/jg/git/bee-swarm/.cache/jev-tui-20260916/plz-before`.
- Native evaluator: `/home/jg/git/bee-swarm/crates/eval/target/release/please-eval`.
- Existing local-model Python environment: `/home/jg/git/bee-swarm/.cache/decision-poc-venv/bin/python`.

**All work in this conversation remains uncommitted.** A fresh checkout from HEAD will omit it. Preserve modified and untracked files, ignored caches, frozen requests, raw responses and failed attempts. Do not reset/clean, reinstall model environments unnecessarily, regenerate a completed experiment into its old output path, or discard earlier work while preparing a PR.

Modified tracked files currently include Cargo.lock, README.md, ci/check-cli-dependencies.sh, ci/check-no-credential-leak.sh, crates/cli/Cargo.toml, crates/cli/src/args.rs, crates/cli/src/main.rs, crates/judge/src/lib.rs and docs/attribution.md. The Jev client, command, TUI, tests, all experiment script directories and research documents are untracked. Inspect `git status --short` before editing or staging. This is a combined backlog of earlier work, not a clean single-feature diff.

Read the repository constitution at `/home/jg/git/bee-swarm/.specify/memory/constitution.md`. No applicable AGENTS.md was found in this checkout or its ancestors. The evaluator is deliberately excluded from the shipping Cargo workspace. Keep that boundary.

## What works now

In an interactive WSL terminal:

```bash
plz clap
# Explicit UI, optionally preloaded:
plz clap --tui candidate.txt --context docs/jev-context.example.json --provenance caller-provided
```

- Bare `plz clap` / `plz jev` opens the TUI when stdin and stdout are terminals.
- Paste text, or clear the input with Ctrl+U and press F2 to use a file path.
- Enter the caller's task, boundary scope, allowed/forbidden actions and source.
- The form builds one ToolActions boundary. Existing `--context` JSON can represent multiple/other boundaries; it is displayed read-only and preserved exactly.
- Key comes from a masked in-memory field or TYPESAFE_API_KEY. It is never saved with advice.
- F3 previews exact outgoing JSON locally. F5 / Ctrl+R sends one request.
- Editing is locked while a request runs in a worker thread. No automatic retry.
- Result shows final advisory relation, native choice, probabilities, confidence, returned model, token usage and identities.
- Ctrl+S exports advice JSON to the selected path using create-new semantics; never overwrites existing files. Unix files are created with permissions 0600.
- PgUp/PgDn scrolls results; Esc/Ctrl+C closes. Minimum size is 90 columns by 30 rows.
- Editing assessment fields clears stale displayed advice. Changing only the save path retains it.
- Explicit input/context arguments without --tui still produce JSON for scripts.
- Bare redirected invocation is a usage error, not a hidden API request.
- UI exit status is the most recent assessment: 1 conflict, 2 indeterminate/error, 3 aligned/material. Closing before an assessment returns 0.

The key is not installed or persisted. A previous temporary key was used in authorized tests. **Do not put a credential in this handoff, source, shell arguments, manifests or logs.** Use the masked field, hidden input or an already configured environment credential.

### Code map

All following paths are under `/home/jg/git/bee-swarm/`:

| Area | Files |
|---|---|
| Shared Jev request, parser, transport, in-memory credential | crates/judge/src/jev.rs |
| API contracts/property tests | crates/judge/tests/jev.rs |
| Thin JSON/interactive dispatch | crates/cli/src/jev.rs |
| Interactive app, editor, terminal rendering, worker and tests | crates/cli/src/jev_tui.rs |
| CLI arguments / alias / feature dispatch | crates/cli/src/args.rs; crates/cli/src/main.rs |
| CLI integration and disabled-feature checks | crates/cli/tests/jev.rs; crates/cli/tests/jev_disabled.rs |
| User guide and caller-context example | docs/jev.md; docs/jev-context.example.json |
| Dependency/credential guards | ci/check-cli-dependencies.sh; ci/check-no-credential-leak.sh |

Default CLI features are judge+tui. The optional tui feature implies judge, Ratatui 0.29 and Crossterm 0.28. The locked dependency chain includes instability 0.3.7; newer versions pulled a higher Rust requirement. Newly introduced dependency manifests were checked against the declared Rust 1.85 baseline, but an entire build on Rust 1.85 was not separately run.

`--no-default-features --features judge` supplies JSON-only Jev; `--no-default-features` supplies the offline scanner without Jev or terminal dependencies. No evaluator/Python/cache dependency is needed to use the TUI.

### Advisory and request boundaries

The shipping client and TUI still use the **original four-way Choice recipe**, not research H. A working UI is not a claim of model readiness.

- Fixed HTTPS endpoint: https://api.typesafe.ai/v1/systemone; redirects refused.
- Default model alias: jev-latest; recent responses identified jev-1.13.0.
- Candidate and context caps: 16 KiB each; encoded request 64 KiB; response 16 KiB.
- Strict UTF-8, caller context validation, no truncation, 30-second deadline.
- Strict response schema, duplicate/missing fields refused, finite bounded scores, unit-sum tolerance 0.001, selected label must match a maximum.
- Uncalibrated gates: top support >=0.70, margin >=0.15, confidence >=0.50; otherwise indeterminate.
- Provider credential reflection is rejected before displaying or saving a response.
- Input hashes, context identity, recipe/request/response hashes, native values and usage are retained.
- Evidence spans remain empty. No invented evidence, verdict mutation, suppression or release authority.
- Ordinary plz scan behavior is unchanged. Jev is only called explicitly.

## Validation already completed

Evidence is in `/home/jg/git/bee-swarm/.cache/jev-tui-20260916/summary.json`, with validation.json/log, installed-verification.json, smoke-offline.json, smoke-live.json and rendered test buffers alongside it.

Passed:
- 11 interactive UI contracts and 6 default-feature Jev CLI contracts.
- Existing 9 Jev parser/request/property contracts and 5 local HTTP transport tests.
- Full workspace credential-canary suite with uncaptured output checked for leakage.
- Workspace Clippy with warnings denied and formatting checks.
- Full no-default-feature CLI suite and JSON-only judge configuration.
- Core dependency allow-list, offline CLI dependency guard, core isolation and WebAssembly build.
- Release build and installation via `cargo install --path crates/cli --locked --force`.
- Render checks at 90x30 and 120x40, plus small-terminal fallback.
- Actual PTY form entry, preview, masked credentials, missing-key handling and terminal restoration.
- One successful synthetic live request through the installed TUI: aligned_instruction; jev-1.13.0; 615 input / 53 output tokens; exit 3. Advice export and absence of the key from terminal/output were checked.
- Byte-identical scanner stdout/stderr and exit codes against the previous installed binary on benign, injection and Unicode fixtures.

The smoke harness initially matched raw incremental screen bytes incorrectly, and later inherited the parent terminal's size during the live preflight. Both harness issues were fixed with a test-only terminal emulator and a separate controlling PTY. Those failed preflights made **zero API calls**. Test-only pyte dependencies live in the cache, not the product.

Windows visual previews: `C:/Users/jg/benchmark-preview/jev-tui-20260916/`. These are test-rendered layouts, not benchmark results.

## Measured model work, in order

### Local-model Phase 2A completed

The older decision-model-next-steps handoff says Phase 2A is pending; that status is superseded.

G1 GLiClass, N1 DeBERTa and N2 ModernBERT adapters and data were implemented and tested. Development macro recall was 0%, 30.0% and 15.8%, respectively; all had zero fully correct context groups. N1 was strongest but no operating point passed calibration. No fine-tuning, Colab training or independent holdout was run.

Read:
- `/home/jg/git/bee-swarm/docs/research/decision-model-phase-2-result-2026-09-16.md`
- `/home/jg/git/bee-swarm/crates/eval/scripts/decision_poc_v2/`
- `/home/jg/git/bee-swarm/.cache/decision-poc-v2-20260916/`

Colab Pro remains an available later option, not an executed training workflow.

### Initial live Jev comparison

1,950 existing cases across development, calibration, shuffled contexts, challenges and the artifact pilot. Original contextual macro recall 65.6%; analysis-only recall 0/120; conflicts 120/120; missing-context wrong determinate answers 45/120. Artifact prompt was separate from contextual CLI advice: 246/330 attacks found and 1/300 benign false alarm, with abstentions also reported.

Read `docs/research/jev-comparison-2026-09-16.md`, `crates/eval/scripts/decision_jev/`, and `.cache/decision-jev-20260916/`.

### First contextual follow-up

Four variants on 156 cases. Focused questions improved analysis recognition and missing-permission abstention but reduced conflict recall/coverage. No variant passed the preset screen; the 600-case confirmation was not run.

Read `docs/research/jev-context-followup-result-2026-09-16.md`, `crates/eval/scripts/jev_followup/`, and `.cache/jev-context-followup-20260916/`.

### Latest usage-pattern experiment

204 cases, 816 API calls, 1,020 verified native replay rows. Four live recipes and one decoder-only variant sharing responses. On the same original 120-case slice:

| Recipe | Macro recall | Analysis recognized | Conflicts | Answerable coverage |
|---|---:|---:|---:|---:|
| C: fresh previous focused recipe | 65.6% | 15/30 | 20/30 | 63/90 |
| P: C with component-scoped validation | 65.6% | 15/30 | 20/30 | 63/90 |
| R: revised questions, model chooses workflow | 75.6% | 14/30 | 27/30 | 71/90 |
| H: caller chooses workflow, concise question | 85.6% | 18/30 | 30/30 | 78/90 |
| X: caller routing plus examples | 81.1% | 14/30 | 30/30 | 76/90 |

H across the full 204-case screen: 69/69 conflicts, 32/33 aligned requests, 42/42 correct missing/contradictory-permission abstentions, 41/60 analysis passages recognized, 17 analysis abstentions and 2 false conflicts. Native analysis choices were no-redirection 51/60 and redirection 9/60; gating is only part of the problem. H used 55.1% fewer recorded input+output tokens than C; latency was similar, about 450 ms median. Pricing was unknown.

**No variant passed every preset gate.** H missed analysis recall, answerable coverage and supplementary recall. No 600-case confirmation occurred. More examples hurt; component-scoped validation changed no final decisions on identical captures.

All data are exposed, same-author development evidence. Delivery copies repeat underlying text. H/X receive explicit caller metadata and are not model-only gains with identical inputs. C is a fresh focused-recipe baseline, not a fresh rerun of the shipping four-way prompt. The 85.6% figure is not deployment accuracy and not the current TUI's measured score.

Read:
- `/home/jg/git/bee-swarm/docs/research/jev-usage-plan-2026-09-16.md`
- `/home/jg/git/bee-swarm/docs/research/jev-usage-result-2026-09-16.md`
- `/home/jg/git/bee-swarm/crates/eval/scripts/jev_usage/`
- `/home/jg/git/bee-swarm/.cache/jev-usage-20260916/`
- Windows report: `C:/Users/jg/benchmark-preview/jev-usage-20260916/report.html`

All experiment requests/code/labels/thresholds were frozen before inference. Raw invalid responses and failures remain retained. Native capture replay reports zero remote requests; real API counts, timing and usage are stored separately. Do not present replay overhead as inference latency.

## Recommended next work

These are recommendations for the next task, not work already completed or authority to change model thresholds/defaults.

### 1. Make repeated personal use convenient

Add named caller-context presets and a read-only saved-advice viewer to the existing TUI:
- Save/load the caller-owned task, boundaries and provenance as an explicitly chosen local file.
- Keep API keys out of presets and result files.
- Do not silently persist candidate text or session history; make saving input an explicit user choice.
- Preserve multiple boundary kinds and completeness fields instead of flattening imported context into one tool-action rule.
- Reopen saved advice without invoking Jev. Validate schema/numeric bounds and escape terminal controls; a saved JSON file is untrusted input.
- Display recipe/model and input identity so a prior result cannot be mistaken for advice about a newly edited input.
- Preserve CLI JSON compatibility and exit statuses. Test offline first with the existing client/response fixtures.
- Improve small-terminal navigation if normal use shows 90x30 is too restrictive.

Start here for product usefulness. Review the existing uncommitted work as a whole before preparing a focused commit or PR; do not stage unrelated material automatically.

### 2. Resolve analysis-versus-redirection labeling and validation

Before more prompt tuning, prepare a review packet covering:
- Plain imperative text presented for analysis.
- A quoted or narrated attack being discussed.
- An active instruction to abandon the caller's analysis task.
- Mixed quotation plus a direct instruction addressed to the current assistant.
- Misleading claims of educational purpose or authorization.
- Missing, contradictory and action/resource-mismatched permissions.

Obtain review without showing Jev outcomes, record disagreements, and reserve fresh workflow families for a genuinely untouched holdout. The existing 600-case partition has been exposed in earlier development; it can be used for development confirmation, not rebranded as a blind holdout. Prepare useful review materials even if independent review cannot happen immediately.

### 3. Evaluate caller-directed routing as a separate versioned recipe

H is the strongest direction to investigate. Port exact behavior only into an explicitly named opt-in recipe after its caller-context mapping is defined and tested:
- Caller selects analysis versus action-review mode; never infer it from candidate authority claims.
- Analysis asks only whether the candidate actively redirects the processing task.
- Action review checks explicit task limits and action/resource permissions.
- Missing/contradictory permission stays unknown.
- Keep the original recipe available and preserve identities/output compatibility.
- Freeze changes and request budget before inference; include a fresh contemporaneous baseline and candidate-only/context-only controls.
- Calibrate thresholds on separate reviewed calibration data. Do not lower thresholds just to recover the current 17 abstentions.
- Promote a default only after the predeclared gates and fresh reviewed evaluation support it. Until then the supported TUI can continue using its existing advisory recipe.

Do not begin another full 1,950-case sweep or Colab training by default. Neither addresses the current label/analysis bottleneck as directly.

## Useful commands

From a WSL terminal:

```bash
cd /home/jg/git/bee-swarm
git status --short
plz clap
# Focused implementation checks:
cargo test -p please-cli --locked
cargo test -p please-judge --test jev --locked
# Existing benchmark results, no API request:
crates/eval/target/release/please-eval bench view --run .cache/jev-usage-20260916/run-screen
```

The complete validation command list is recorded in `.cache/jev-tui-20260916/validation.json`. Re-run checks appropriate to new changes; do not rerun old inference or the one-off smoke export into an existing output filename without a reason.

## Suggested next-task prompt

Continue Please in /home/jg/git/bee-swarm using docs/research/jev-next-steps-handoff-2026-09-16.md. Preserve all current uncommitted work and ignored experiment evidence. The interactive plz clap TUI is implemented and installed; begin by reviewing its current contracts, then add reusable caller-context presets and a read-only saved-advice viewer with explicit local saves, no key persistence, safe rendering and no network on reopen. Preserve the JSON CLI and advisory boundary. Keep research H separate from the default recipe; prepare an independently reviewable analysis/redirection case packet before further tuning. Do not claim the existing 85.6% development result as the shipping TUI's performance. Validate the changes, update documentation/attribution, and report completed work plus remaining review dependencies.
