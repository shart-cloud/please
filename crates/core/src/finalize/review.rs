//! Review bindings and caller-owned release authority. Obtaining a review is separate from applying it.

use super::types::{JudgeReport, Reason, Verdict};
use crate::{ruleset::Bands, RulesetId, ScanPolicy};
use sha2::{Digest, Sha256};

/// A host-derived decision names evidence in a captured request, never a naked list position.
pub struct EvidenceDecision {
    pub evidence_id: String,
    pub role: crate::SpanRole,
    pub relation: crate::SpanRelation,
    pub judgement: crate::SpanJudgement,
}

/// Requesting a second opinion does not grant it permission to lower the enforcement result.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum ReviewAuthority {
    #[default]
    Advisory,
    /// The reviewer may remove findings from active scoring, potentially releasing the input.
    MayRelease,
}

impl ReviewAuthority {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Advisory => "advisory",
            Self::MayRelease => "may_release",
        }
    }
}

/// Immutable evidence and configuration as seen by one ordinary review request.
///
/// Engine scans carry input and policy identity. Low-level finalization callers can bind synthetic
/// evidence too; this does not invent input provenance for them. Network request assembly separately
/// requires a matching complete-input digest. Coverage gaps may accumulate while a review is pending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewScope {
    input_digest: Option<String>,
    policy: Option<ScanPolicy>,
    ruleset: RulesetId,
    engine: crate::EngineId,
    ml: Option<crate::verdict::MlReport>,
    bands: Bands,
    max_observations: u32,
    reasons: Vec<Reason>,
    suppressed: Vec<Reason>,
}

impl ReviewScope {
    pub fn capture(verdict: &Verdict) -> Self {
        Self {
            input_digest: verdict.input_digest().map(str::to_owned),
            policy: verdict.scan_policy().map(ScanPolicy::analysis_identity),
            ruleset: verdict.ruleset().clone(),
            engine: verdict.engine().clone(),
            ml: verdict.ml().cloned(),
            bands: *verdict.bands(),
            max_observations: verdict.analysis().bounds.max_observations,
            reasons: verdict.analysis().reasons().to_vec(),
            suppressed: verdict.analysis().suppressed().to_vec(),
        }
    }

    /// Original evidence remains available even when an authorized review changes the active result.
    pub fn reasons(&self) -> &[Reason] {
        &self.reasons
    }

    pub fn suppressed(&self) -> &[Reason] {
        &self.suppressed
    }

    /// Audit identifier for this version of the binding representation. Validation uses exact equality,
    /// not this digest. This is not a model-supplied request identifier or an authentication token.
    pub fn identity(&self) -> String {
        format!(
            "{:x}",
            Sha256::digest(format!("ordinary-review-v2:{self:?}"))
        )
    }

    pub fn evidence_ids(&self) -> Vec<String> {
        let request_id = self.identity();
        self.reasons
            .iter()
            .enumerate()
            .map(|(index, _)| format!("{:x}", Sha256::digest(format!("{request_id}:{index}"))))
            .collect()
    }

    pub fn report(
        &self,
        model: &str,
        prompt_version: &str,
        features: crate::Features,
        decisions: Vec<EvidenceDecision>,
        model_severity: Option<u8>,
    ) -> Result<JudgeReport, &'static str> {
        let ids = self.evidence_ids();
        let mut seen = vec![false; ids.len()];
        let mut judgements = Vec::with_capacity(decisions.len());
        for decision in decisions {
            let index = ids
                .iter()
                .position(|id| id == &decision.evidence_id)
                .ok_or("review names evidence outside its request")?;
            if seen[index] {
                return Err("review contains duplicate evidence decisions");
            }
            seen[index] = true;
            judgements.push(crate::SpanVerdict {
                reason_index: index,
                role: decision.role,
                relation: decision.relation,
                judgement: decision.judgement,
            });
        }
        Ok(self.bind(JudgeReport::new(
            model,
            prompt_version,
            features,
            judgements,
            model_severity,
        )))
    }

    /// Bind host-derived decisions to the request that supplied their positional namespace.
    /// Capture the scope before obtaining decisions, never reconstruct it at application time.
    pub fn bind(&self, report: JudgeReport) -> JudgeReport {
        report.with_scope(self.clone())
    }

    pub(super) fn valid_for(&self, verdict: &Verdict) -> bool {
        self == &Self::capture(verdict)
    }
}
