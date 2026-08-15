//! `plz` — scan prompts, skills, and artifacts for prompt-injection attempts.
//!
//! A thin wrapper holding **no detection logic** (Principle V). It translates a command line into a
//! [`please_core::ScanPolicy`], reads targets, and renders verdicts. Anything `plz` can decide, an embedder
//! calling the library decides identically — the CLI must never become a privileged side channel with
//! behaviour the library lacks.
//!
//! # Exit status is the contract
//!
//! | Code | Meaning |
//! |---|---|
//! | 0 | clean |
//! | 1 | risk found at or above the threshold |
//! | 3 | risk found below the threshold |
//! | 2 | inconclusive — analysis did not complete |
//! | 64 | usage error |
//! | 70 | internal error |
//!
//! `3` is distinct from `0` because a caller that wants to allow-but-log needs to tell "nothing found" from
//! "something found, under your bar". `64` and `70` follow `sysexits.h` and are distinct from every risk
//! outcome, so a hook can never mistake "the tool did not run" for "the input is fine".

mod args;
mod render;
mod target;

use clap::Parser;
use please_core::verdict::Outcome;
use please_core::{Engine, Verdict};

use args::{Args, Command};
use target::Target;

// Exit codes. Named rather than inline so the contract is legible in one place.
const EXIT_CLEAN: i32 = 0;
const EXIT_RISK_AT_THRESHOLD: i32 = 1;
const EXIT_INCONCLUSIVE: i32 = 2;
const EXIT_RISK_BELOW_THRESHOLD: i32 = 3;
const EXIT_USAGE: i32 = 64;
const EXIT_INTERNAL: i32 = 70;

fn main() {
    std::process::exit(run());
}

fn run() -> i32 {
    let args = Args::parse();
    let Command::Scan(scan_args) = args.command;
    let policy = scan_args.policy();

    let engine = match Engine::builtin() {
        Ok(engine) => engine,
        // The embedded rule set failing to load is a build defect, not a user error — hence 70.
        Err(e) => {
            eprintln!("plz: the built-in rule set failed to load: {e}");
            return EXIT_INTERNAL;
        }
    };

    for warning in engine.warnings() {
        eprintln!("plz: warning: {warning}");
    }

    let targets = match target::resolve(&scan_args.targets) {
        Ok(targets) => targets,
        Err(e) => {
            eprintln!("plz: {e}");
            return EXIT_USAGE;
        }
    };

    let mut verdicts: Vec<Verdict> = Vec::new();
    for item in targets {
        match item {
            Target::Content { bytes, reference } => {
                verdicts.push(engine.scan(&bytes, &policy, reference));
            }
            // An unreadable file is inconclusive for that target and the walk continues (FR-032a). It is
            // constructed here because the core never opens a file, so the caller doing the I/O owns this
            // case — and skipping it instead is the one thing that must not happen.
            Target::Unreadable { reference, detail } => {
                eprintln!(
                    "plz: cannot read {}: {detail}",
                    reference.name.as_deref().unwrap_or("?")
                );
                verdicts.push(please_core::finalize::unreadable_target(
                    reference,
                    detail,
                    engine.ruleset_id().clone(),
                ));
            }
        }
    }

    // Results to stdout, diagnostics to stderr. Nothing but results ever reaches stdout, in either format:
    // a warning interleaved into a machine-readable stream is a broken contract, not a cosmetic issue.
    let mut out = String::new();
    for verdict in &verdicts {
        render::verdict(&mut out, verdict, scan_args.explain);
    }
    render::summary(&mut out, &verdicts);
    print!("{out}");

    exit_code(&verdicts, policy.threshold)
}

/// Derive the process status from every verdict, by the precedence
/// `risk_found` > `inconclusive` > `clean` (FR-032b).
///
/// The precedence is what makes a multi-target summary trustworthy: a tree in which every readable file is
/// clean but one file could not be read summarises as inconclusive, not clean.
fn exit_code(verdicts: &[Verdict], threshold: please_core::verdict::RiskLevel) -> i32 {
    let mut worst = Outcome::Clean;
    let mut at_threshold = false;

    for verdict in verdicts {
        if verdict.outcome().rank() > worst.rank() {
            worst = verdict.outcome();
        }
        if verdict.outcome() == Outcome::RiskFound && verdict.is_at_or_above(threshold) {
            at_threshold = true;
        }
    }

    match worst {
        Outcome::Clean => EXIT_CLEAN,
        Outcome::Inconclusive => EXIT_INCONCLUSIVE,
        Outcome::RiskFound if at_threshold => EXIT_RISK_AT_THRESHOLD,
        Outcome::RiskFound => EXIT_RISK_BELOW_THRESHOLD,
    }
}
