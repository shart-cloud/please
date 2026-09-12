//! Input-bound ML-only review. No response can select a structural reason by index.
use sha2::{Digest, Sha256};

use super::{add_gap, order};
use crate::ruleset::Bands;
use crate::verdict::{DetectionClass, IncompleteCause, MlMode, MlReport, Reason, Verdict};
use crate::CoverageGap;

pub const CONTRACT_VERSION: &str = "ml-boundary-review-v1";

pub(crate) fn input_digest(input: &[u8]) -> String {
    format!("{:x}", Sha256::digest(input))
}

pub(super) fn matches_classifier(reason: &Reason, report: &MlReport) -> bool {
    reason.rule_id() == "ml.classifier"
        && reason.class() == DetectionClass::AgentDirected
        && reason.chain().is_empty()
        && report.threshold() <= 1000
        && report.segments().iter().any(|segment| {
            segment.span() == reason.span()
                && matches!(segment.mode(), MlMode::Classify | MlMode::Both)
                && segment
                    .probability()
                    .is_some_and(|p| p >= report.threshold() && p <= 1000)
        })
}

/// True only for a retained observation minted by ML finalization against this input and report.
pub fn eligible(verdict: &Verdict, reason: &Reason) -> bool {
    verdict.ml().is_some_and(|report| {
        reason.ml_origin() == Some(report)
            && report.input_digest().is_some()
            && report.input_digest() == verdict.input_digest()
            && matches_classifier(reason, report)
    })
}

/// Frozen host mapping. Its private reasons survive unrelated structural demotion/reordering.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MlReviewScope {
    input_digest: String,
    report: MlReport,
    candidates: Vec<Reason>,
    policy: crate::ScanPolicy,
    ruleset: crate::RulesetId,
    bands: Bands,
}

impl MlReviewScope {
    pub fn capture(verdict: &Verdict, input: &[u8]) -> Result<Self, &'static str> {
        if verdict.ml_review().is_some() {
            return Err("ML review requires complete findings and an unreviewed ML tier");
        }
        let digest = input_digest(input);
        if verdict.input_digest() != Some(digest.as_str()) {
            return Err("ML review input does not match the scanned input");
        }
        let report = verdict.ml().ok_or("no ML report")?.clone();
        let candidates: Vec<_> = verdict
            .analysis()
            .reasons()
            .iter()
            .filter(|reason| eligible(verdict, reason))
            .cloned()
            .collect();
        if candidates.is_empty() {
            return Err("no eligible ML observations");
        }
        let text = std::str::from_utf8(input).map_err(|_| "ML review requires UTF-8")?;
        for (i, reason) in candidates.iter().enumerate() {
            let span = reason.span();
            if span.is_empty()
                || text.get(span.start..span.end).is_none()
                || candidates[..i].contains(reason)
            {
                return Err("ambiguous or invalid ML candidate scope");
            }
        }
        Ok(Self {
            input_digest: digest,
            report,
            candidates,
            policy: verdict
                .scan_policy()
                .ok_or("missing scan policy")?
                .analysis_identity(),
            ruleset: verdict.ruleset().clone(),
            bands: *verdict.bands(),
        })
    }

    pub fn candidates(&self) -> &[Reason] {
        &self.candidates
    }

    /// Opaque identity binds the input, provenance, candidates and scan policy without disclosing them.
    pub fn identity(&self) -> String {
        input_digest(format!("{self:?}").as_bytes())
    }

    fn valid_for(&self, verdict: &Verdict) -> bool {
        verdict.ml_review().is_none()
            && verdict.input_digest() == Some(self.input_digest.as_str())
            && verdict.ml() == Some(&self.report)
            && verdict
                .scan_policy()
                .map(crate::ScanPolicy::analysis_identity)
                .as_ref()
                == Some(&self.policy)
            && verdict.ruleset() == &self.ruleset
            && verdict.bands() == &self.bands
            && verdict
                .analysis()
                .reasons()
                .iter()
                .filter(|r| eligible(verdict, r))
                .count()
                == self.candidates.len()
            && self.candidates.iter().all(|candidate| {
                eligible(verdict, candidate)
                    && verdict
                        .analysis()
                        .reasons()
                        .iter()
                        .filter(|r| *r == candidate)
                        .count()
                        == 1
            })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum MlReviewOutcome {
    SupportedViolation,
    NoSupportedViolation,
    Indeterminate,
}

/// Minimal public attribution. Model-written rationales stay in the caller's private response capture.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct MlReviewReport {
    pub model: String,
    pub contract_version: String,
    pub request_id: String,
    pub outcomes: Vec<MlReviewOutcome>,
    authority: super::review::ReviewAuthority,
    #[cfg_attr(feature = "serde", serde(skip))]
    scope: MlReviewScope,
    #[cfg_attr(feature = "serde", serde(skip))]
    context_sufficient: bool,
}

impl MlReviewReport {
    /// Trusted integration seam, like JudgeReport::new. Responses must pass the judge crate's parser.
    /// The finalizer independently enforces scope, ML provenance, and context sufficiency.
    pub fn new(
        scope: MlReviewScope,
        model: &str,
        request_id: &str,
        outcomes: Vec<MlReviewOutcome>,
        context_sufficient: bool,
    ) -> Self {
        Self {
            model: crate::sanitize::sanitize_str(model, 256).0,
            contract_version: CONTRACT_VERSION.into(),
            request_id: request_id.into(),
            outcomes,
            authority: super::review::ReviewAuthority::Advisory,
            scope,
            context_sufficient,
        }
    }

    pub fn authority(&self) -> super::review::ReviewAuthority {
        self.authority
    }
}

/// Apply a validated response atomically. No partial response can clear a subset of candidates.
pub fn apply(verdict: Verdict, report: MlReviewReport, bands: &Bands) -> Verdict {
    if verdict.bands() != bands {
        return unavailable(verdict, "ML review calibration does not match the scan");
    }
    apply_with_authority(verdict, report, super::review::ReviewAuthority::Advisory)
}

pub fn apply_with_authority(
    verdict: Verdict,
    mut report: MlReviewReport,
    authority: super::review::ReviewAuthority,
) -> Verdict {
    if !report.scope.valid_for(&verdict)
        || report.outcomes.len() != report.scope.candidates.len()
        || report.contract_version != CONTRACT_VERSION
        || report.request_id.len() != 64
        || !report.request_id.bytes().all(|b| b.is_ascii_hexdigit())
        || (!report.context_sufficient
            && report
                .outcomes
                .contains(&MlReviewOutcome::NoSupportedViolation))
    {
        return unavailable(
            verdict,
            "ML review scope, context, or response identity is invalid",
        );
    }
    let mut state = verdict.into_analysis();
    let mut kept = Vec::new();
    for mut reason in state.reasons {
        let index = report.scope.candidates.iter().position(|r| r == &reason);
        if authority == super::review::ReviewAuthority::MayRelease
            && index.is_some_and(|i| report.outcomes[i] == MlReviewOutcome::NoSupportedViolation)
        {
            reason.demote_by_ml_review();
            state.suppressed.push(reason);
        } else {
            kept.push(reason);
        }
    }
    state.reasons = kept;
    order(&mut state.suppressed);
    if !report.context_sufficient || report.outcomes.contains(&MlReviewOutcome::Indeterminate) {
        state.incomplete.push(
            CoverageGap::failure(
                IncompleteCause::TierUnavailable,
                "ML review is indeterminate or caller context is incomplete",
            )
            .into_incompleteness(),
        );
    }
    report.authority = authority;
    state.ml_review = Some(report);
    state.finish()
}

pub fn unavailable(verdict: Verdict, detail: &str) -> Verdict {
    add_gap(
        verdict,
        CoverageGap::failure(IncompleteCause::TierUnavailable, detail),
    )
}
