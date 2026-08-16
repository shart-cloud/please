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

use args::{Args, Command, Format};
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
    // `try_parse` rather than `parse`, because `parse` exits the process itself with clap's default code of
    // 2 — which is this CLI's code for INCONCLUSIVE. A caller branching on the status would read "you passed
    // an unrecognised `--classes` value" as "analysis did not complete", and the doc comment above promises
    // exactly the opposite: that a hook can never mistake "the tool did not run" for a scan outcome.
    //
    // Found at 002 T047, by removing a `--classes` value and asserting the rejection. It predates this
    // feature — every invalid argument has always exited 2 — and was invisible because
    // `every_documented_exit_code_is_distinct` asserts distinctness over a literal array of the six numbers
    // rather than over what the binary actually returns.
    //
    // `use_stderr()` separates a real error from `--help` and `--version`, which clap also delivers as
    // `Err` and which are a successful run of what the user asked for.
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) => {
            let _ = e.print();
            return if e.use_stderr() {
                EXIT_USAGE
            } else {
                EXIT_CLEAN
            };
        }
    };
    // A `match` rather than the irrefutable `let Command::Scan(..)` this was until feature 004. The enum
    // had one variant, so destructuring it was infallible; `judge` makes it a real choice.
    //
    // On a DEFAULT build the `Judge` arm is compiled out and clippy is right that the match has one arm
    // again. Writing it as a `let` under `cfg` instead would mean two spellings of the same dispatch that
    // have to be kept in agreement, and the whole point of this line is that there is one.
    #[cfg_attr(not(feature = "judge"), allow(clippy::infallible_destructuring_match))]
    let scan_args = match args.command {
        Command::Scan(scan_args) => scan_args,
        #[cfg(feature = "judge")]
        Command::Judge(judge_args) => return run_judge(&judge_args),
    };
    let policy = scan_args.policy();

    let engine = match build_engine(&scan_args) {
        Ok(engine) => engine,
        Err(code) => return code,
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

    // The judgement tier, if this build has it and this invocation asked for it (FR-401). Built once
    // rather than per target: credential resolution reads the environment, and doing that in a loop would
    // make a directory walk's behaviour depend on when each target happened to be reached.
    #[cfg(feature = "judge")]
    let judge = if scan_args.judge {
        let resolution = please_judge::Resolution::from_env();
        // FR-415, before any request. A warning after the fact is a warning about something already sent.
        for warning in resolution.warnings() {
            eprintln!("plz: warning: {warning}");
        }
        // T038a. Cost is per target and multiplies. The spec puts optimising that out of scope and NOT
        // surprising anyone with it in scope, so say the number before spending it.
        if targets.len() > 1 {
            eprintln!(
                "plz: --judge makes one request per target with findings; {} targets queued",
                targets.len()
            );
        }
        let mut judge = please_judge::Judge::new(resolution);
        if let Some(seconds) = scan_args.judge_timeout {
            judge = judge.with_timeout(std::time::Duration::from_secs(seconds));
        }
        Some(judge)
    } else {
        None
    };

    let mut verdicts: Vec<Verdict> = Vec::new();
    for item in targets {
        match item {
            Target::Content { bytes, reference } => {
                let verdict = engine.scan(&bytes, &policy, reference);
                // `Verdict → Verdict`, infallible. Every failure mode is a coverage gap inside the returned
                // verdict rather than an `Err` this loop could quietly skip (R4, FR-402).
                #[cfg(feature = "judge")]
                let verdict = match &judge {
                    Some(judge) => judge.review(verdict, &bytes, engine.bands()),
                    None => verdict,
                };
                verdicts.push(verdict);
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
    //
    // The format switch is here and only here. Every verdict is already accumulated, so nothing threads
    // through the scan loop and the two renderers see exactly the same values.
    let mut out = String::new();
    match scan_args.format() {
        Format::Human => {
            for verdict in &verdicts {
                render::human::verdict(&mut out, verdict, scan_args.explain);
            }
            render::human::summary(&mut out, &verdicts);
        }
        // No summary line: for JSON the answer to "how did the whole run go" is the array plus the exit
        // code, and a summary field would be a second home for the FR-032b precedence.
        Format::Json => render::json::render(&mut out, &verdicts),
    }
    print!("{out}");

    exit_code(&verdicts, policy.threshold)
}

/// `plz judge --check` — answer *"what would you do"* without doing it (FR-414).
///
/// **Makes no network request**, which is what makes it safe to run anywhere: it cannot leak a credential
/// to an endpoint by testing it. With several variables commonly set at once and a proxy in the path, "why
/// is it hitting the wrong host with the wrong header" is otherwise a bad afternoon.
///
/// Exits `0` on a successful report even when no credential resolves. It is a diagnostic, not a health
/// check — "you have nothing configured" is a successful answer to the question asked, and a scan that
/// needs a credential and lacks one already exits `2` through the `TierUnavailable` path.
#[cfg(feature = "judge")]
fn run_judge(args: &args::JudgeArgs) -> i32 {
    if !args.check {
        eprintln!("plz judge: nothing to do. Pass --check to report the resolved configuration.");
        return EXIT_USAGE;
    }
    // Diagnostics on stderr, the report on stdout — the same split as a scan, so `plz judge --check` can
    // be piped somewhere without a warning corrupting the stream.
    print!("{}", please_judge::Resolution::from_env().describe());
    EXIT_CLEAN
}

/// Build the engine this invocation asks for (FR-023, T102/T103).
///
/// Returns the exit code to use on failure, because **whose fault it is decides which code**, and that
/// distinction is the substance of this function:
///
/// | Failure | Code | Why |
/// |---|---|---|
/// | the **built-in** rule set will not load | `70` | a build defect. The rules are embedded; a user cannot cause this and cannot fix it |
/// | a **caller's** rule set will not load, or names an unknown id to disable | `64` | an invocation fault (`contracts/cli.md`, `contracts/ruleset.md`) |
///
/// Before this existed there was one arm and it returned 70 for both, so a typo in someone's TOML reported
/// itself as an internal error worth filing a bug about.
///
/// Filesystem access stays here rather than in the core: `Ruleset::from_toml` takes text, deliberately, so
/// that the same engine runs in a browser. [`target::read_rules`] does the opening.
fn build_engine(scan_args: &args::ScanArgs) -> Result<Engine, i32> {
    // No rule flags: the built-in set, and a failure is ours.
    if scan_args.rules.is_empty() && scan_args.disable_rule.is_empty() {
        return Engine::builtin().map_err(|e| {
            eprintln!("plz: the built-in rule set failed to load: {e}");
            EXIT_INTERNAL
        });
    }

    let mut builder = Engine::builder();
    for path in &scan_args.rules {
        let source = target::read_rules(path).map_err(|e| {
            eprintln!("plz: {e}");
            EXIT_USAGE
        })?;
        // Parsed here rather than handed to the builder as text, so the diagnostic can name the file. A
        // `RulesetError` already names the offending *rule*; with several `--rules` it does not know which
        // file that rule came from, and the operator has to.
        let ruleset = please_core::Ruleset::from_toml(&source).map_err(|e| {
            eprintln!("plz: {}: {e}", path.display());
            EXIT_USAGE
        })?;
        builder = builder.add_ruleset(ruleset);
    }
    for id in &scan_args.disable_rule {
        builder = builder.disable(id.clone());
    }

    // Resolution errors — an unknown suppression, too many rules after layering — are the caller's, so 64.
    // Replacement warnings are NOT errors and reach stderr through `engine.warnings()` below, unchanged.
    builder.build().map_err(|e| {
        eprintln!("plz: {e}");
        EXIT_USAGE
    })
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
