//! The `plz` command surface.
//!
//! Every flag here maps to a field of [`please_core::ScanPolicy`], because policy belongs to the caller
//! (FR-006). The CLI's job is to translate a command line into that policy and render what comes back —
//! it holds no detection logic, so anything `plz` can decide, an embedder calling the library can decide
//! identically (Principle V).
//!
//! `--format json` and the rule-set flags arrive with User Story 2 and 4. They are absent rather than
//! stubbed: a flag that parses and then fails is worse than one that does not exist, because a script
//! written against it looks correct.

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
