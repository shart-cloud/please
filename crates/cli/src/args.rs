//! The `plz` command surface.
//!
//! Every flag here maps to a field of [`please_core::ScanPolicy`], because policy belongs to the caller
//! (FR-006). The CLI's job is to translate a command line into that policy and render what comes back —
//! it holds no detection logic, so anything `plz` can decide, an embedder calling the library can decide
//! identically (Principle V).
//!
//! Every flag `contracts/cli.md` documents now exists. The rule-set flags arrived at 001 T102/T103 and
//! `--format` at T070, several features later than planned — they were absent rather than stubbed in the
//! meantime, on the principle that a flag which parses and then fails is worse than one that does not
//! exist, because a script written against it looks correct.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use please_core::verdict::{DetectionClass, RiskLevel};
use please_core::ScanPolicy;

#[derive(Debug, Parser)]
#[command(
    name = "plz",
    about = "Scan prompts, skills, and artifacts for prompt-injection attempts",
    long_about = "PLEASE — Prompt-Layer Evaluation And Security Engine.\n\n\
                  Reports what it finds; it does not decide what to do about it. Exit status is the \
                  contract: 0 clean, 1 at or above threshold, 3 below threshold, 2 inconclusive, \
                  64 usage error, 70 internal error.\n\n\
                  Accuracy is currently verified against curated fixtures, NOT measured against a real \
                  corpus. See docs/limits.md before relying on it.",
    version
)]
pub struct Args {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, clap::Subcommand)]
pub enum Command {
    /// Scan one or more targets.
    Scan(ScanArgs),

    /// Inspect the judgement tier's configuration. **Makes no network request.**
    ///
    /// Absent on a default build, for the same reason `--judge` is: a security tool that accepts a
    /// command it cannot honour is worse than one that refuses it. On a default build this is an unknown
    /// subcommand and exits 64.
    #[cfg(feature = "judge")]
    Judge(JudgeArgs),
}

#[cfg(feature = "judge")]
#[derive(Debug, Parser)]
pub struct JudgeArgs {
    /// Report which credential variable would be used, which are ignored, and the resolved endpoint —
    /// without making a request (FR-414).
    ///
    /// Safe to run anywhere: it cannot leak a credential to an endpoint by testing it, and no line of its
    /// output contains a credential value (FR-413, SC-404).
    #[arg(long)]
    pub check: bool,
}

#[derive(Debug, Parser)]
pub struct ScanArgs {
    /// Files, directories, or `-` for standard input. Defaults to standard input.
    pub targets: Vec<String>,

    /// Risk band at or above which the exit status reports "risk found".
    #[arg(long, value_enum, default_value_t = Band::High)]
    pub threshold: Band,

    /// Show rule descriptions and decode chains.
    #[arg(long)]
    pub explain: bool,

    /// Detection classes to run. Repeatable; defaults to all.
    #[arg(long, value_enum)]
    pub classes: Vec<Class>,

    /// Report matches inside code blocks, quotes, and examples that would normally be suppressed.
    ///
    /// Raises the false-positive rate substantially on documentation. Useful when scanning content that
    /// should contain no examples at all.
    #[arg(long)]
    pub no_suppress_in_quotes: bool,

    /// Maximum input size in bytes. Larger inputs report inconclusive rather than clean.
    #[arg(long)]
    pub max_input_bytes: Option<u64>,

    /// Maximum nested-decoding depth.
    #[arg(long)]
    pub max_decode_depth: Option<u8>,

    /// Maximum reasons reported per target.
    #[arg(long)]
    pub max_reasons: Option<u32>,

    /// A TOML rule set to layer on top of the built-in rules. Repeatable.
    ///
    /// Additions are applied in argument order and a rule whose id matches an existing one **replaces**
    /// it, reported as a warning on stderr so overriding is never accidental. A malformed rule set is a
    /// usage error naming the offending rule; the scan does not proceed on a partially loaded set
    /// (FR-023, FR-024).
    #[arg(long, value_name = "PATH")]
    pub rules: Vec<PathBuf>,

    /// Disable a rule by id. Repeatable.
    ///
    /// Applied **after** additions, so a rule can be added by one layer and disabled by another.
    /// Disabling an id that does not exist is a usage error rather than a silent no-op: the usual cause
    /// is a typo, and a typo that quietly leaves a rule enabled defeats the point of disabling it.
    #[arg(long, value_name = "ID")]
    pub disable_rule: Vec<String>,

    /// Ask the judgement tier for a second opinion on what was found.
    ///
    /// Makes one network request per target that produced findings. An unavailable judge is
    /// **inconclusive, never clean** — see `docs/limits.md`.
    #[cfg(feature = "judge")]
    #[arg(long, overrides_with = "no_judge")]
    pub judge: bool,

    /// Do not ask the judgement tier. The default, and the way to reproduce a structural verdict exactly.
    ///
    /// `overrides_with` on both, so **the last flag wins**: a wrapper script appending `--no-judge` can
    /// override a config that supplied `--judge`. Two independent booleans would make
    /// `--judge --no-judge` mean whichever the code happened to check first.
    #[cfg(feature = "judge")]
    #[arg(long, overrides_with = "judge")]
    pub no_judge: bool,

    /// Seconds to wait for the judge before giving up (FR-420).
    ///
    /// **Whole seconds, not `5s`.** A duration parser would be a new crate in the *default* dependency
    /// graph of `plz`, for a flag the default build does not have — precisely the leak
    /// `ci/check-cli-dependencies.sh` exists to catch.
    #[cfg(feature = "judge")]
    #[arg(long, value_name = "SECONDS")]
    pub judge_timeout: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Band {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl From<Band> for RiskLevel {
    fn from(b: Band) -> Self {
        match b {
            Band::None => RiskLevel::None,
            Band::Low => RiskLevel::Low,
            Band::Medium => RiskLevel::Medium,
            Band::High => RiskLevel::High,
            Band::Critical => RiskLevel::Critical,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Class {
    Override,
    Concealment,
    Confusable,
    Boundary,
    Solicitation,
    AgentDirected,
}

impl From<Class> for DetectionClass {
    fn from(c: Class) -> Self {
        match c {
            Class::Override => DetectionClass::Override,
            Class::Concealment => DetectionClass::Concealment,
            Class::Confusable => DetectionClass::Confusable,
            Class::Boundary => DetectionClass::Boundary,
            Class::Solicitation => DetectionClass::Solicitation,
            Class::AgentDirected => DetectionClass::AgentDirected,
        }
    }
}

impl ScanArgs {
    /// Build the scan policy this invocation asks for.
    ///
    /// Starts from the library defaults and overrides only what was given, so a default `plz scan` and a
    /// default `Engine::scan` behave identically — the CLI must not be a second source of policy.
    pub fn policy(&self) -> ScanPolicy {
        let mut policy = ScanPolicy {
            threshold: self.threshold.into(),
            suppress_in_quotes: !self.no_suppress_in_quotes,
            ..ScanPolicy::default()
        };
        if !self.classes.is_empty() {
            policy.classes = self
                .classes
                .iter()
                .map(|c| DetectionClass::from(*c))
                .collect();
        }
        if let Some(v) = self.max_input_bytes {
            policy.max_input_bytes = v;
        }
        if let Some(v) = self.max_decode_depth {
            policy.max_decode_depth = v;
        }
        if let Some(v) = self.max_reasons {
            policy.max_reasons = v;
        }
        policy
    }
}
