# Jev local files: completed 2026-09-17

Named caller-context presets and a read-only saved-advice viewer are implemented,
tested and installed in /home/jg/.cargo/bin/plz.

## Use

Start plz clap in a WSL terminal.

- F6: save context/provenance under a chosen file path and preset name.
- F7: load that preset without changing candidate input or the masked key.
- F8: open existing advice offline.
- F4: return from historical advice to the assessment form.
- Preset shortcut: plz clap --preset my-context.json
- Viewer shortcut: plz clap --view-advice old-advice.json

Presets preserve full typed boundaries and completeness metadata. Imported
contexts remain read-only. Saves are explicit, non-overwriting, private on Unix,
and exclude candidate text and credentials. No session history is persisted.
Saved advice is bounded and validated, escapes terminal controls, and shows
recorded model/recipe/input identities. The historical viewer blocks editing,
saving and submission; it makes no request and does not set a new assessment
exit status. Identities in saved files are unverified claims, not signatures.

## Validation

Passed: 15 UI contracts; 12 Jev parser/request/property contracts; 7 default
Jev CLI contracts; full workspace uncaptured credential-canary suite; Clippy
with warnings denied; formatting; offline CLI suite; JSON-only configuration;
core dependency/isolation checks; WebAssembly build; debug/release builds.

Actual terminal tests exercised save/load, reopening the prior live export,
read-only controls and terminal restoration at 90x30. Release startup tests
covered presets and historical advice, including the viewer at 60x20.
Scanner stdout, stderr and exit codes matched the prior installed binary on
three fixtures. The exact Jev request matched byte-for-byte. The installed
binary hash matches the tested release.

No new API calls were made. There was no new accuracy experiment or Rust 1.85
toolchain build. The original four-way recipe and all thresholds are unchanged.
The assessment form still requires 90x30; the new file dialogs/viewer work smaller.

Evidence: .cache/jev-local-files-20260917/ under the repository.
The previous installed executable is retained there as plz-before.

## Review dependencies

The adjacent review-packet contains 24 synthetic cases, blank independent
reviewer forms, a rubric, disagreement/adjudication procedure, coverage index
and file hashes. No model outcomes or author labels are supplied. Two independent
reviews and adjudication remain pending; no invitations were sent.

This packet is exposed development material. A curator still needs to reserve
fresh workflow families and reviewed calibration/holdout data outside tuning.
Caller-directed H remains research only. Freeze mapping, recipe, gates and
API budget before any further inference; do not promote defaults from the
existing 85.6% development result.

All existing uncommitted work and prior experiment directories remain in place.
Nothing was staged, committed, pushed, reset or cleaned.
