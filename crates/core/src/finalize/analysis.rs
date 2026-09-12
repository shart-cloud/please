//! Retained evidence and tier reports. Display projections never feed evidence back into analysis.

use super::{evidence::Observation, plan::Bounds, types::*, Attribution};

/// Retained excerpts use this fixed byte budget, independently of report display settings.
/// Review also receives the bounded original document. This is an excerpt, not an analysis window.
pub const RETAINED_EXCERPT_BYTES: usize = 4096;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DisplayLimits {
    pub max_reasons: u32,
    pub max_excerpt_bytes: u32,
}

/// The authoritative record for one scan. Findings and suppressions share an observation budget.
/// Original evidence for an applied review remains in that report's captured scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Analysis {
    pub(super) reasons: Vec<Reason>,
    pub(super) suppressed: Vec<Reason>,
    pub(super) incomplete: Vec<Incompleteness>,
    pub(super) target: TargetRef,
    pub(super) ruleset: RulesetId,
    pub(super) engine: EngineId,
    pub(super) bands: crate::ruleset::Bands,
    pub(super) bounds: Bounds,
    pub(super) judge: Option<JudgeReport>,
    pub(super) ml: Option<MlReport>,
    pub(super) input_digest: Option<String>,
    pub(super) ml_review: Option<super::ml_review::MlReviewReport>,
    pub(super) scan_policy: Option<crate::ScanPolicy>,
}

impl Analysis {
    pub(super) fn new(bounds: Bounds, attribution: Attribution) -> Self {
        Self {
            reasons: Vec::new(),
            suppressed: Vec::new(),
            incomplete: Vec::new(),
            target: attribution.target,
            ruleset: attribution.ruleset,
            bands: attribution.bands,
            engine: EngineId::current(),
            bounds,
            judge: None,
            ml: None,
            input_digest: None,
            ml_review: None,
            scan_policy: None,
        }
    }

    /// All active findings, in deterministic order, with retained neutralized excerpts.
    pub fn reasons(&self) -> &[Reason] {
        &self.reasons
    }
    pub fn suppressed(&self) -> &[Reason] {
        &self.suppressed
    }

    /// Produce a shortened report while retaining the complete analysis for later composition.
    pub fn report(mut self, limits: DisplayLimits) -> Verdict {
        self.bounds.max_reasons = limits.max_reasons;
        self.bounds.max_excerpt_bytes = limits.max_excerpt_bytes;
        self.finish()
    }

    fn reserve_observation(&mut self) -> bool {
        if self.reasons.len() + self.suppressed.len() < self.bounds.max_observations as usize {
            return true;
        }
        if !self
            .incomplete
            .iter()
            .any(|g| g.cause() == IncompleteCause::MaxObservations)
        {
            self.incomplete.push(
                super::evidence::CoverageGap::bound(
                    IncompleteCause::MaxObservations,
                    self.bounds.max_observations as u64,
                    "additional observations exceeded the retained analysis budget",
                )
                .into_incompleteness(),
            );
        }
        false
    }

    pub(super) fn observe(
        &mut self,
        mut observation: Observation,
        context: Option<QuotingContext>,
    ) {
        if !self.reserve_observation() {
            return;
        }
        if let Some(context) = context {
            observation.suppressed_by = Some(context);
        }
        let reason = super::into_reason(observation, RETAINED_EXCERPT_BYTES);
        if context.is_some() {
            self.suppressed.push(reason);
        } else {
            self.reasons.push(reason);
        }
    }

    pub(super) fn observe_ml(&mut self, observation: Observation, report: &MlReport) {
        if !self.reserve_observation() {
            return;
        }
        let mut reason = super::into_reason(observation, RETAINED_EXCERPT_BYTES);
        reason.mark_ml();
        if super::ml_review::matches_classifier(&reason, report) {
            reason.bind_ml(report);
        }
        self.reasons.push(reason);
    }

    pub(super) fn finish(mut self) -> Verdict {
        super::order(&mut self.reasons);
        super::order(&mut self.suppressed);
        Verdict::new(self)
    }
}
