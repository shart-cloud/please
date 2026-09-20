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
//! Reviews are advisory by default. The caller can explicitly grant `ReviewAuthority::MayRelease`,
//! allowing demotions to remove findings from scoring and potentially release the input. A reviewer
//! with that authority is inside the enforcement trust boundary; retained audit evidence does not
//! prevent a release. No review adds findings or raises their severity.
//!
//! **Not an opinion.** The model answers factual questions about text from closed option sets. *This crate*
//! computes the score ([`score`], plan D4). A model that is not scoring anything has nothing to inflate.
//!
//! # Fail-closed, always
//!
//! Unreachable, unauthenticated, timed out, unparseable, asked about a document too large, or asked to
//! judge evidence beyond its request budget — every one is a
//! [`TierUnavailable`](please_core::verdict::IncompleteCause::TierUnavailable) coverage gap, and therefore
//! `Inconclusive`. **Never `Clean`** (FR-402). A network dependency in a security path is a fail-open
//! waiting to happen; that requirement is what stops it being one.
//!
//! [`Judge::review`] is infallible for the same reason `Engine::scan` is: an `Err` is something a caller
//! can `unwrap_or_default()` into something cheerful, and a coverage gap in the returned verdict is not.

pub mod client;
pub mod credential;
mod envelope;
pub mod jev;
pub mod ml_review;
pub mod request;
pub mod response;
pub mod score;

use crate::ml_review::ContextWire;
use std::time::Duration;

use please_core::finalize;
use please_core::ruleset::Bands;
use please_core::verdict::{IncompleteCause, Verdict};
use please_core::CoverageGap;

pub use credential::{Credential, CredentialSource, Resolution};
pub use please_core::finalize::review::ReviewAuthority;
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
    authority: ReviewAuthority,
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
            authority: ReviewAuthority::Advisory,
        }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Caller authorization for ordinary and ML review decisions. MayRelease puts this reviewer
    /// inside the enforcement trust boundary: all-demoted findings can produce a successful exit.
    pub fn with_authority(mut self, authority: ReviewAuthority) -> Self {
        self.authority = authority;
        self
    }

    pub fn authority(&self) -> ReviewAuthority {
        self.authority
    }

    /// Non-secret effective request recipe, excluding input, context and credentials.
    pub fn inference_metadata(&self) -> serde_json::Value {
        let mut metadata = client::inference_metadata(&self.resolution);
        metadata["authority"] = serde_json::to_value(self.authority).expect("authority serializes");
        metadata["timeout_ms"] = serde_json::json!(self.timeout.as_millis());
        metadata
    }

    pub fn resolution(&self) -> &Resolution {
        &self.resolution
    }

    /// Review the scan's findings under this judge's caller-selected authority.
    ///
    /// Input identity and calibration must match the scan before any network request. The request
    /// freezes evidence and policy, and the response is applied only to that binding. Default authority
    /// is advisory; `with_authority(ReviewAuthority::MayRelease)` explicitly permits release.
    pub fn review(&self, verdict: Verdict, input: &[u8], bands: &Bands) -> Verdict {
        let context = verdict.scan_policy().and_then(|p| p.caller_context.clone());
        match context {
            Some(context) => self.review_with_ml_context(verdict, input, bands, &context),
            None => self.review_routed(verdict, input, bands, None),
        }
    }

    /// Explicitly opt in with caller-owned context. Structural and ML responses use separate finalizers.
    /// The default CLI and `review` retain the prepared baseline routing.
    pub fn review_with_ml_context(
        &self,
        verdict: Verdict,
        input: &[u8],
        bands: &Bands,
        context: &ml_review::ReviewContext,
    ) -> Verdict {
        if verdict.bands() != bands {
            return unavailable(verdict, "review calibration does not match the scan".into());
        }
        if verdict.analysis().reasons().is_empty() {
            return verdict;
        }
        if verdict
            .scan_policy()
            .and_then(|p| p.caller_context.as_ref())
            != Some(context)
        {
            return unavailable(
                verdict,
                "review context does not match the caller context bound to this scan".into(),
            );
        }
        if !verdict
            .analysis()
            .reasons()
            .iter()
            .any(|r| r.ml_origin().is_some())
        {
            let source = verdict
                .scan_policy()
                .map(|p| p.effective_provenance())
                .unwrap_or_default();
            let wire = match context.wire(
                source,
                verdict.scan_policy().map(|p| p.profile).unwrap_or_default(),
            ) {
                Ok(wire) => wire.to_string(),
                Err(detail) => return unavailable(verdict, detail.into()),
            };
            let verdict = if context.validate(source) == Ok(true) {
                verdict
            } else {
                unavailable(
                    verdict,
                    "caller context is incomplete for requested boundary review".into(),
                )
            };
            return self.review_routed(verdict, input, bands, Some(&wire));
        }
        let request = match ml_review::MlReviewRequest::assemble(&verdict, input, context) {
            Ok(request) => request,
            Err(detail) => return unavailable(verdict, detail.into()),
        };
        // Freeze ML mapping before structural demotions reorder the reasons.
        let verdict = self.review_routed(verdict, input, bands, Some(request.caller_context()));
        match client::send_ml_review(&self.resolution, &request, self.timeout) {
            Ok(raw) => request.apply_envelope_with_authority(
                verdict,
                &raw,
                self.resolution.model(),
                self.authority,
            ),
            Err(error) => unavailable(verdict, error.to_string()),
        }
    }

    pub fn review_ml(
        &self,
        verdict: Verdict,
        input: &[u8],
        bands: &Bands,
        context: &ml_review::ReviewContext,
    ) -> Verdict {
        if verdict.bands() != bands {
            return unavailable(verdict, "review calibration does not match the scan".into());
        }
        if !verdict
            .analysis()
            .reasons()
            .iter()
            .any(|r| r.ml_origin().is_some() || r.rule_id() == "ml.classifier")
        {
            return verdict;
        }
        let request = match ml_review::MlReviewRequest::assemble(&verdict, input, context) {
            Ok(request) => request,
            Err(detail) => return unavailable(verdict, detail.into()),
        };
        match client::send_ml_review(&self.resolution, &request, self.timeout) {
            Ok(raw) => request.apply_envelope_with_authority(
                verdict,
                &raw,
                self.resolution.model(),
                self.authority,
            ),
            Err(error) => unavailable(verdict, error.to_string()),
        }
    }

    fn review_routed(
        &self,
        verdict: Verdict,
        input: &[u8],
        bands: &Bands,
        caller_context: Option<&str>,
    ) -> Verdict {
        let structural_only = caller_context.is_some();
        if verdict.bands() != bands {
            return unavailable(verdict, "review calibration does not match the scan".into());
        }
        let assembled = if structural_only {
            request::JudgeRequest::assemble_structural(&verdict, input)
        } else {
            request::JudgeRequest::assemble(&verdict, input)
        };
        let request = match assembled {
            Ok(request) => request,
            // FR-404. Nothing to arbitrate, so no request — and **no coverage gap either**. This is the one
            // "did not judge" path that is not a failure: a verdict with no observations has nothing for a
            // second opinion to be about, and marking it inconclusive would turn every clean scan under
            // `--judge` into an inconclusive one.
            Err(request::NotAsked::NoObservations) => return verdict,
            Err(request::NotAsked::InvalidScope(detail)) => {
                return unavailable(verdict, detail.into())
            }
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

        let sent = if let Some(caller_context) = caller_context {
            let content = format!(
                "Caller-owned boundary context (JSON):\n{}\n\n{}",
                caller_context,
                request.user_content()
            );
            if content.len() > ml_review::MAX_REQUEST_BYTES {
                return unavailable(
                    verdict,
                    "encoded structural review with caller context exceeds the byte limit".into(),
                );
            }
            client::send_with_schema_captured(
                &self.resolution,
                client::tool_schema(),
                &content,
                self.timeout,
            )
        } else {
            client::send_captured(&self.resolution, &request, self.timeout)
        };
        let raw = match sent {
            Ok(value) => value,
            Err(e) => return unavailable(verdict, e.to_string()),
        };

        let report = match request.parse_envelope(&raw, self.resolution.model()) {
            Ok(report) => report,
            Err(detail) => return unavailable(verdict, detail.into()),
        };

        finalize::rejudge_with_authority(verdict, report, self.authority)
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
