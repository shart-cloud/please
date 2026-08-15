//! `plz` — scan prompts, skills, and artifacts for prompt-injection attempts.
//!
//! **Phase 1 scaffold.** Argument parsing, target reading, rendering, and status-code mapping arrive
//! with User Story 1 and 2 (tasks T060–T075). This binary exists so the workspace builds from the
//! first commit.
//!
//! This crate is a thin wrapper and holds **no detection logic** (constitution Principle V). Anything
//! `plz` can decide, an embedder calling `please-core` can decide identically — the CLI must never
//! become a privileged side channel with behaviour the library lacks.

fn main() {
    // Exit code 70 is the sysexits "internal error" slot, and is deliberately distinct from every
    // risk verdict: a caller must never be able to mistake "the tool did not run" for "the input is
    // clean" (contracts/cli.md).
    eprintln!(
        "plz: not yet implemented — {} {} scaffold, see specs/001-structural-detection-cli/tasks.md",
        please_core::ENGINE_NAME,
        please_core::ENGINE_VERSION,
    );
    std::process::exit(70);
}
