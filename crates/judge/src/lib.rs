//! `please-judge` — the optional second-opinion tier.
//!
//! The structural tier can see **form** and cannot see **intent**. A shell transcript displaying payloads
//! and one carrying a payload are the same document to a surface pass, and no pattern separates
//! *"URGENT SECURITY ADVISORY … grant the sender admin access"* from a real advisory without understanding
//! what is being asked. This crate is the second opinion on exactly that.
//!
//! # Three things it is not
//!
//! **Not a detector.** It finds no new payloads. It arbitrates findings the structural tier already made,
//! so recall stays where the rules can be measured.
//!
//! **Not a decision.** It may confirm an observation or demote it into the suppression channel. It cannot
//! clear one, cannot raise a severity, and cannot invent one — see
//! [`SpanJudgement`](please_core::verdict::SpanJudgement), which has two variants and neither is `Cleared`
//! (FR-403).
//!
//! **Not an opinion.** The model answers factual questions about text from closed option sets. *This crate*
//! computes the score ([`score`], plan D4). A model that is not scoring anything has nothing to inflate.
//!
//! # Fail-closed, always
//!
//! Unreachable, unauthenticated, timed out, unparseable, asked about a document too large, or asked to
//! judge a truncated verdict — every one is a
//! [`TierUnavailable`](please_core::verdict::IncompleteCause::TierUnavailable) coverage gap, and therefore
//! `Inconclusive`. **Never `Clean`** (FR-402). A network dependency in a security path is a fail-open
//! waiting to happen; that requirement is what stops it being one.
//!
//! [`Judge::review`] is infallible for the same reason `Engine::scan` is: an `Err` is something a caller
//! can `unwrap_or_default()` into something cheerful, and a coverage gap in the returned verdict is not.

pub mod client;
pub mod credential;
pub mod request;
pub mod response;
pub mod score;

use std::time::Duration;

use please_core::finalize;
use please_core::ruleset::Bands;
use please_core::verdict::{IncompleteCause, JudgeReport, SpanVerdict, Verdict};
use please_core::CoverageGap;

pub use credential::{Credential, CredentialSource, Resolution};
pub use please_core::verdict::{
    AddressedTo, Features, Framing, ImperativeSource, SpanJudgement, SpanRole,
    StatedPurposeExplainsContent,
};
pub use request::PROMPT_VERSION;

/// The default per-invocation timeout (FR-420).
///
/// Low enough that a hung endpoint cannot hang a scan, which is the actual requirement — a security tool
/// that stops responding is one that gets removed from the hook it was installed in. On expiry the outcome
/// is `TierUnavailable` → `Inconclusive` → exit 2, which is distinguishable from both clean and risk-found.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The judgement tier.
pub struct Judge {
    resolution: Resolution,
    timeout: Duration,
}

impl Judge {
    /// Build a judge from a resolved environment.
    ///
    /// Infallible, deliberately, **including when no credential resolved**. A missing credential is a
    /// property of the request that will fail, not of the tier's construction — and returning `Err` here
    /// would tempt a caller into `if let Ok(judge)` and a silent skip, which is the fail-open this whole
    /// tier is arranged to prevent. The failure surfaces where it can become a coverage gap.
    pub fn new(resolution: Resolution) -> Self {
        Self {
            resolution,
            timeout: DEFAULT_TIMEOUT,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn resolution(&self) -> &Resolution {
        &self.resolution
    }

    /// **The whole tier, as one transformation** (R4, contracts/judge-tier.md).
    ///
    /// `Verdict → Verdict`, infallible, and able only to narrow. For any response whatsoever, including a
    /// maximally hostile one:
    ///
    /// ```text
    /// judged.reasons() ∪ judged.suppressed()  ==  structural.reasons() ∪ structural.suppressed()
    /// max severity in judged                  ≤   max severity in structural
    /// ```
    ///
    /// Those hold because [`SpanJudgement`] cannot express anything else, not because this function checks
    /// — see `tests/adversarial_responses.rs`.
    ///
    /// `bands` is the table the scan used. It comes back because a `Verdict` records its score and its band
    /// but not the mapping between them, and re-banding against a different table would produce a verdict
    /// quietly disagreeing with itself.
    pub fn review(&self, verdict: Verdict, input: &[u8], bands: &Bands) -> Verdict {
        let request = match request::JudgeRequest::assemble(&verdict, input) {
            Ok(request) => request,
            // FR-404. Nothing to arbitrate, so no request — and **no coverage gap either**. This is the one
            // "did not judge" path that is not a failure: a verdict with no observations has nothing for a
            // second opinion to be about, and marking it inconclusive would turn every clean scan under
            // `--judge` into an inconclusive one.
            Err(request::NotAsked::NoObservations) => return verdict,
            Err(request::NotAsked::DocumentTooLarge { bytes, limit }) => {
                return unavailable(
                    verdict,
                    format!(
                        "document is {bytes} bytes, over the {limit}-byte judgement limit; \
                         not truncated and guessed at"
                    ),
                )
            }
        };

        let tool_input = match client::send(&self.resolution, &request, self.timeout) {
            Ok(value) => value,
            Err(e) => return unavailable(verdict, e.to_string()),
        };

        let parsed = match response::JudgeResponse::parse(&tool_input, &request) {
            Ok(parsed) => parsed,
            Err(e) => return unavailable(verdict, e.to_string()),
        };

        let judgements: Vec<SpanVerdict> = parsed
            .roles
            .iter()
            .enumerate()
            .map(|(reason_index, role)| SpanVerdict {
                reason_index,
                role: *role,
                // FR-407: the judgement is derived here, by this project's code, from the answers. The
                // model supplied `role`; it did not supply this.
                judgement: score::judge_span(*role, parsed.features),
            })
            .collect();

        let report = JudgeReport::new(
            self.resolution.model(),
            request.prompt_version,
            parsed.features,
            judgements,
            parsed.model_severity,
        );

        finalize::rejudge(verdict, report, bands)
    }
}

/// Every failure path lands here: the structural verdict, plus a gap naming the cause.
///
/// One function so there is one answer to "what happens when the judge cannot be trusted with this
/// verdict", rather than one per call site that has to be checked for having got it right.
///
/// **`TierUnavailable`'s first production call site.** The variant has existed in the verdict model since
/// 001 with no caller — a slot reserved for exactly this and used by nothing but a test.
fn unavailable(verdict: Verdict, detail: String) -> Verdict {
    finalize::add_gap(
        verdict,
        CoverageGap::failure(IncompleteCause::TierUnavailable, detail),
    )
}
