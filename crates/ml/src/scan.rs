//! Complete-document classification, composed with structural evidence through core's finalizer.

use please_core::finalize::{self, evidence::CoverageGap, plan::ScanPlan};
use please_core::ruleset::Bands;
use please_core::verdict::{IncompleteCause, MlMode, MlReport, MlSegmentResult, Span};
use please_core::{ScanPolicy, Verdict};

use crate::{observe_with_impact, MlLoadResult, Outcome, Segment, ML_CLASS};

/// Classify the complete original UTF-8 input, including documents with no structural findings.
/// The model chunks long inputs and returns their maximum probability. The reported span is the
/// whole document, not a claim to have localized the highest-scoring model chunk. Source/quotation
/// and export policies govern structural scanning; they are not model inputs or ML suppressors.
/// Run before judge review. Requested but unavailable inference always adds a coverage gap.
pub fn scan(
    model: &MlLoadResult,
    structural: Verdict,
    input: &[u8],
    policy: &ScanPolicy,
    bands: &Bands,
) -> Verdict {
    let plan = ScanPlan::resolve(policy);
    if input.len() as u64 > policy.max_input_bytes {
        return unavailable(structural, "ML input exceeds the caller's byte limit");
    }
    if !plan.admits(ML_CLASS) {
        return unavailable(
            structural,
            "ML requires the agent_directed class enabled by the caller",
        );
    }
    let model = match model {
        MlLoadResult::Loaded(model) => model,
        MlLoadResult::Unavailable(detail) => return unavailable(structural, detail),
    };
    let text = match std::str::from_utf8(input) {
        Ok(text) => text,
        Err(_) => {
            return unavailable(
                structural,
                "ML requires valid UTF-8; bytes were not normalized",
            )
        }
    };
    let classification = match model.classify_detailed(text) {
        Outcome::Ok(probability) => probability,
        Outcome::Failed(detail) => return unavailable(structural, &detail),
        Outcome::NotApplicable => {
            return unavailable(structural, "requested model is not a classifier")
        }
    };
    let probability = classification.raw_score;
    let span = Span::new(0, input.len());
    let segment = Segment {
        span,
        text,
        probability: Some(probability),
    };
    let observations = observe_with_impact(&segment, model.config(), policy.ml_impact)
        .into_iter()
        .collect();
    let report = MlReport::new(
        &model.config().model_id,
        &model.config().revision,
        model.digest(),
        model.config().threshold,
        vec![MlSegmentResult::new(
            span,
            MlMode::Classify,
            Some(probability),
            None,
        )],
    );
    finalize::with_ml(
        structural,
        observations,
        report
            .with_input(input)
            .with_impact(policy.ml_impact)
            .with_inference(model.identity().clone(), classification.windows),
        plan.bounds(),
        bands,
    )
}

fn unavailable(verdict: Verdict, detail: &str) -> Verdict {
    finalize::add_gap(
        verdict,
        CoverageGap::failure(IncompleteCause::TierUnavailable, detail),
    )
}
