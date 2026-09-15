# Prompt-injection test bench

`please-eval bench` compares systems over identity-bound case packs without adding adapter dependencies to a
shipping crate. Version 1 executes artifact detection and contextual alignment. It does not execute tools or
agents.

Linux or Ubuntu under WSL is the supported host. Python 3 is required only for the committed
`contextual-reference.py` process fixture; the in-process PLEASE adapter and pack tooling do not require it.

## Commands

- `bench pack digest/check` authors and verifies immutable packs.
- `bench system` verifies a system manifest and executable/rule references.
- `bench experiment` validates the complete plan without creating output.
- `bench run` writes a new incomplete-then-complete run directory.
- `bench report` reconstructs stratified JSON or Markdown from verified rows.
- `bench compare` compares only identity-compatible semantic decisions.
- `bench exposure` writes a new prompt-free exposure history.

## External protocol

The child is a long-lived sequential process. Standard output is protocol-only JSONL. The first host message
is a `handshake`; after an identity-matching response, each `case` receives one `result`. All envelopes use
`please-bench-jsonl/v1` and reject unknown fields. Candidate bytes are hex encoded. Ground truth, runner
policy, normalizers, and labels are never sent.

The child starts with a cleared environment, an explicit manifest environment, a run-owned working directory,
piped streams, and its own process group. A timeout, crash, malformed/duplicate/wrong-id/oversized response,
EOF, stderr overflow, or restart exhaustion becomes a row coverage state. Stderr is captured once per spawn
in `run.json`; it is never assigned to a case. Case-specific adapter diagnostics belong in the identity-bound
JSON response. The runner never invokes a shell
and never treats these outcomes as clean.

`max_restarts` is the number of replacement child starts permitted after the initial start. Version 1 accepts
at most 100 replacements. The stdout reader has a one-line bounded queue, so a newline-spamming adapter is
backpressured by its pipe rather than buffered without limit by the runner.

The caller must provide an exact executable SHA-256. `network_capable: true` requires a network-enabled
experiment; ordinary runs reject it. Offline mode is a selection control, not a kernel network sandbox.
A subprocess may opt into a caller-provided `sandbox_command` prefix, such as `unshare -n`; the exact
prefix is recorded in `run.json`. Reports distinguish this enforcement hook from an unsandboxed
"declared offline" run.
At run start, each verified subprocess is copied into the run directory, verified again, made read-only,
and used for every start and restart. The copy is re-verified before each spawn. For script adapters this
freezes the script bytes, not the shebang interpreter (for example `/usr/bin/python3`).

A system manifest selects executable code and is therefore trusted code, not untrusted corpus data.
`network_capable: false` is the manifest author's declaration; without an explicitly configured operating-system
sandbox it does not prove that the child lacks network access. Reports describe this state as declared offline.

Case-pack schema v2 may declare one baseline case for each contextual group. Reports compare that baseline
with every other group member. A group without a declared baseline emits every ordered pair, so pair direction
never depends on lexical case-id adjacency.

## Interpretation

Raw native labels, confidence, evidence, diagnostics, stdout/stderr, cost, and remote-request counts remain
separate from normalization. Artifact and contextual normalizers cannot cross surfaces. Reports show operating
points and required strata before any conclusion, retain failures in coverage, and never describe the
committed development pilot as deployment accuracy.

The canonical examples are `bench/please-mechanism.system.json`,
`bench/contextual-reference.system.json`, and `bench/contextual-pilot.experiment.json`. The Python adapter is an
instrument fixture, not a defense recommendation.

Pack and system paths are resolved relative to the experiment manifest. Exposure paths use the same base but
may be absolute because exposure ledgers are often outputs outside the pack. Taxonomy and asset paths remain
strictly relative to their pack, and executable/rule paths remain strictly relative to their system manifest.

## Results table and HTML report

A successful CLI run creates a standalone, offline `report.html` in the new run directory and prints
a summary table. Add `--tui` to browse results after completion:

```bash
mkdir -p .cache/bench
cargo run --manifest-path crates/eval/Cargo.toml -- bench run \
  --experiment crates/eval/bench/contextual-pilot.experiment.json \
  --out .cache/bench/presentation-demo --tui
```

Reopen the verified results without executing systems again:

```bash
cargo run --manifest-path crates/eval/Cargo.toml -- bench view \
  --run .cache/bench/presentation-demo
```

Use Tab/Left/Right to switch Summary, Source, Delivery, and Technique; Up/Down or j/k to select a row;
Home/End to jump; q/Esc/Ctrl-C to exit. The selected row shows coverage failures, timing, and operating
point details. The terminal must be at least 90 columns by 24 rows; larger terminals fit more detail.
This first version browses completed results; it does not display live test progress.

For scripts or redirected output, omit `--tui` or export explicitly:

```bash
cargo run --manifest-path crates/eval/Cargo.toml -- bench report \
  --run .cache/bench/presentation-demo --format html --out /tmp/bench-report.html
cargo run --manifest-path crates/eval/Cargo.toml -- bench report \
  --run .cache/bench/presentation-demo --format table
```

HTML includes system identities and operating points, strata, failure details, the contextual matrix,
paired changes, and subprocess diagnostics. It uses no JavaScript, external fonts, or network assets.
All views consume the same verified report; incomplete or corrupt runs are rejected. Verification
establishes saved-result integrity, not a release-quality gate.

Rates use integer per-mille arithmetic and show their denominators. Recall includes failed attack rows
as misses; contextual accuracy includes all contextual rows. False-alarm rates use all benign rows and
must be read with coverage (zero false alarms with zero completed rows is not successful coverage).
Empty denominators show N/A. Summary rows are per system and surface; technique strata may overlap.
The shipping workspace's dependencies and detection behavior are unchanged.
