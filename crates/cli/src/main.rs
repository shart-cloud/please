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

use std::io::Write;

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

    // What will be scanned, not yet its contents. Reading every target up front made peak memory a
    // function of the corpus rather than of the largest file in it, which `contracts/cli.md` forbids and
    // which a directory of any real size hits.
    let sources = match target::plan(&scan_args.targets) {
        Ok(sources) => sources,
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
        if sources.len() > 1 {
            eprintln!(
                "plz: --judge makes one request per target with findings; {} targets queued",
                sources.len()
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

    // Results to stdout, diagnostics to stderr. Nothing but results ever reaches stdout, in either format:
    // a warning interleaved into a machine-readable stream is a broken contract, not a cosmetic issue.
    //
    // The format switch is here and only here, and it happens BEFORE the loop: the JSON renderer needs the
    // target count to know whether it is writing an object or an array, and `plan` has already established
    // it without reading anything.
    //
    // Locked once and buffered, rather than a `print!` per verdict. `println!` takes the lock and flushes
    // line by line, which over a large walk is a syscall per line for no benefit — and interleaving is not
    // a concern because this is the only thing in the process that writes to stdout.
    let mut emitter = match scan_args.format() {
        Format::Human => render::Emitter::human(scan_args.explain),
        // No summary line for JSON: the answer to "how did the whole run go" is the array plus the exit
        // code, and a summary field would be a second home for the FR-032b precedence.
        Format::Json => render::Emitter::json(sources.len()),
    };
    let stdout = std::io::stdout();
    let mut out = std::io::BufWriter::new(stdout.lock());

    let mut tally = Tally::new(policy.threshold);

    // Load, scan, render, drop — one target at a time. What is resident is the largest single target, not
    // the sum of them, and the first verdict reaches a reader before the second file is opened.
    for source in &sources {
        let target = match target::load(source) {
            Ok(target) => target,
            // Only standard input can fail here, and it is the whole of what was asked for.
            Err(e) => {
                eprintln!("plz: {e}");
                return EXIT_USAGE;
            }
        };

        let verdict = match target {
            Target::Content { bytes, reference } => {
                let verdict = engine.scan(&bytes, &policy, reference);
                // `Verdict → Verdict`, infallible. Every failure mode is a coverage gap inside the returned
                // verdict rather than an `Err` this loop could quietly skip (R4, FR-402).
                #[cfg(feature = "judge")]
                let verdict = match &judge {
                    Some(judge) => judge.review(verdict, &bytes, engine.bands()),
                    None => verdict,
                };
                verdict
            }
            // An unreadable file is inconclusive for that target and the walk continues (FR-032a). It is
            // constructed here because the core never opens a file, so the caller doing the I/O owns this
            // case — and skipping it instead is the one thing that must not happen.
            Target::Unreadable { reference, detail } => {
                eprintln!(
                    "plz: cannot read {}: {detail}",
                    reference.name.as_deref().unwrap_or("?")
                );
                please_core::finalize::unreadable_target(
                    reference,
                    detail,
                    engine.ruleset_id().clone(),
                )
            }
            // A symbolic link to a directory. Reported, never skipped, for the same reason.
            Target::NotTraversed { reference, detail } => {
                eprintln!(
                    "plz: not following {}: {detail}",
                    reference.name.as_deref().unwrap_or("?")
                );
                please_core::finalize::not_traversed(reference, detail, engine.ruleset_id().clone())
            }
        };

        tally.observe(&verdict);
        // Flushed per verdict, not left to the buffer. Without this a reader sees nothing until 8 KiB has
        // accumulated, which for small verdicts is dozens of targets — so a consumer acting on results as
        // they arrive would be reading a walk that is already far ahead of it, and a hook watching a long
        // scan would see nothing at all until it was mostly over.
        //
        // The cost is one write syscall per target rather than per 8 KiB. Against reading and scanning a
        // file that is not measurable, and `BufWriter` still coalesces the many small writes *within* one
        // verdict into that single call, which is most of what the buffer was for.
        if let Err(e) = emitter
            .verdict(&mut out, &verdict)
            .and_then(|()| out.flush())
        {
            return stopped_writing(&e, &mut tally);
        }
    }

    if let Err(e) = emitter.finish(&mut out) {
        return stopped_writing(&e, &mut tally);
    }
    // Explicit, because `BufWriter` swallows a flush failure in `Drop`. A run whose last verdicts never
    // left the buffer must not report the status of a run that was fully delivered.
    if let Err(e) = out.flush() {
        return stopped_writing(&e, &mut tally);
    }

    tally.exit_code()
}

/// The status for a run whose output could not be delivered in full.
///
/// Almost always a reader that went away — `plz scan ./tree | head`. Streaming makes that visible where a
/// single `print!` at the end never noticed it, and the honest answer is **inconclusive**: the caller did
/// not receive every verdict, so they must not act on the ones they did as though that were all of them.
/// Routed through [`Tally::note_gap`] rather than returned directly, so a risk already found still wins by
/// the FR-032b precedence — "I found something and then the pipe closed" is not less serious than the pipe
/// closing.
fn stopped_writing(e: &std::io::Error, tally: &mut Tally) -> i32 {
    if e.kind() == std::io::ErrorKind::BrokenPipe {
        // No diagnostic. A closed pipe is the normal end of `| head`, and stderr is often the same
        // terminal — complaining about it is noise about something the reader did on purpose.
        tally.note_gap();
        return tally.exit_code();
    }
    eprintln!("plz: cannot write results: {e}");
    EXIT_INTERNAL
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

/// The process status, folded over verdicts as they are produced.
///
/// Derives the status by the precedence `risk_found` > `inconclusive` > `clean` (FR-032b). That precedence
/// is what makes a multi-target summary trustworthy: a tree in which every readable file is clean but one
/// file could not be read summarises as inconclusive, not clean.
///
/// An accumulator rather than a function over `&[Verdict]`, because nothing keeps the verdicts any more.
/// The logic is unchanged — it was always a fold over these two values — but it now runs against a stream
/// of one verdict at a time rather than a collection the walk had to hold to the end.
struct Tally {
    worst: Outcome,
    at_threshold: bool,
    threshold: please_core::verdict::RiskLevel,
}

impl Tally {
    fn new(threshold: please_core::verdict::RiskLevel) -> Self {
        Self {
            worst: Outcome::Clean,
            at_threshold: false,
            threshold,
        }
    }

    fn observe(&mut self, verdict: &Verdict) {
        if verdict.outcome().rank() > self.worst.rank() {
            self.worst = verdict.outcome();
        }
        if verdict.outcome() == Outcome::RiskFound && verdict.is_at_or_above(self.threshold) {
            self.at_threshold = true;
        }
    }

    /// Record that the run did not cover everything it was asked to.
    ///
    /// For a gap with no verdict to attach it to — the reader closing the pipe, say. It raises the status
    /// to inconclusive by the same precedence, so it cannot mask a risk already found and cannot leave a
    /// truncated run reporting clean.
    fn note_gap(&mut self) {
        if Outcome::Inconclusive.rank() > self.worst.rank() {
            self.worst = Outcome::Inconclusive;
        }
    }

    fn exit_code(&self) -> i32 {
        match self.worst {
            Outcome::Clean => EXIT_CLEAN,
            Outcome::Inconclusive => EXIT_INCONCLUSIVE,
            Outcome::RiskFound if self.at_threshold => EXIT_RISK_AT_THRESHOLD,
            Outcome::RiskFound => EXIT_RISK_BELOW_THRESHOLD,
        }
    }
}
