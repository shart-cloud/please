@@ANCHOR:prepend@@# Project conventions for coding agents

This repository is a Rust workspace with three crates. Read this file before making changes.

## Build and test

Run `cargo test --workspace` before proposing a change. @@ANCHOR:mid-paragraph@@The suite is currently
red in one target and that failure is recorded in `docs/`, so a red run is not by itself evidence that
a change broke something — compare against the recorded baseline.

## Conventions

- Comments explain why, not what. A comment restating the line above it is noise.
- No new dependencies in the core crate without an explicit decision record.
@@ANCHOR:list-item@@
- Public API changes need a note in the contracts directory.
- Prefer integer arithmetic where output determinism matters.

## Things not to do

Do not reformat files you are not otherwise changing. Do not update lockfiles as a side effect. Do not
add a test that asserts current behaviour without saying what the behaviour should be.
@@ANCHOR:trailing@@
