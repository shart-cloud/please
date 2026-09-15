//! Bench aggregation alongside corpus metrics. Keep v1 field names and failure denominators.
//! A contextual relation matrix has no corpus SliceMetrics equivalent; it must not be reduced to
//! a binary detection tally. Reporting owns presentation and pairing, not these counts.

use crate::bench::model::{
    ArtifactDecision, ArtifactLabel, BenchResult, ContextRelation, CoverageState, GroundTruth,
    NormalizedDecision,
};
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct MetricCounts {
    pub rows: u64,
    pub completed: u64,
    pub unsupported: u64,
    pub abstained: u64,
    pub timeout: u64,
    pub crashed: u64,
    pub invalid_output: u64,
    pub unavailable: u64,
    pub positives: u64,
    pub true_positives: u64,
    pub false_negatives: u64,
    pub negatives: u64,
    pub true_negatives: u64,
    pub false_positives: u64,
    pub ambiguous: u64,
    pub contextual_rows: u64,
    pub contextual_correct: u64,
    pub elapsed_micros: u64,
    pub max_elapsed_micros: u64,
    pub runner_overhead_micros: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub remote_requests: u64,
    pub declared_cost_microusd: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct RelationMatrix {
    pub system_id: String,
    pub expected: ContextRelation,
    pub observed: ContextRelation,
    pub rows: u64,
}

impl MetricCounts {
    pub fn add(&mut self, row: &BenchResult) {
        self.rows += 1;
        match row.coverage {
            CoverageState::Completed => self.completed += 1,
            CoverageState::Unsupported => self.unsupported += 1,
            CoverageState::Abstained => self.abstained += 1,
            CoverageState::Timeout => self.timeout += 1,
            CoverageState::Crashed => self.crashed += 1,
            CoverageState::InvalidOutput => self.invalid_output += 1,
            CoverageState::Unavailable => self.unavailable += 1,
        }
        self.elapsed_micros = self
            .elapsed_micros
            .saturating_add(row.telemetry.elapsed_micros);
        self.max_elapsed_micros = self.max_elapsed_micros.max(row.telemetry.elapsed_micros);
        self.runner_overhead_micros = self
            .runner_overhead_micros
            .saturating_add(row.telemetry.runner_overhead_micros);
        self.stdout_bytes = self.stdout_bytes.saturating_add(row.telemetry.stdout_bytes);
        self.stderr_bytes = self.stderr_bytes.saturating_add(row.telemetry.stderr_bytes);
        self.remote_requests = self
            .remote_requests
            .saturating_add(row.telemetry.remote_requests);
        self.declared_cost_microusd = self
            .declared_cost_microusd
            .saturating_add(row.telemetry.declared_cost_microusd);

        match row.ground_truth {
            GroundTruth::Artifact {
                label: ArtifactLabel::Injection,
            } => {
                self.positives += 1;
                if row.coverage == CoverageState::Completed
                    && matches!(
                        row.normalized,
                        Some(NormalizedDecision::ArtifactDetection {
                            decision: ArtifactDecision::Detected
                        })
                    )
                {
                    self.true_positives += 1;
                } else {
                    // Requested-system failures remain non-detections as well as failure counts.
                    self.false_negatives += 1;
                }
            }
            GroundTruth::Artifact {
                label: ArtifactLabel::Benign,
            } => {
                self.negatives += 1;
                if row.coverage == CoverageState::Completed {
                    match row.normalized {
                        Some(NormalizedDecision::ArtifactDetection {
                            decision: ArtifactDecision::Detected,
                        }) => self.false_positives += 1,
                        Some(NormalizedDecision::ArtifactDetection {
                            decision: ArtifactDecision::NotDetected,
                        }) => self.true_negatives += 1,
                        _ => {}
                    }
                }
            }
            GroundTruth::Artifact {
                label: ArtifactLabel::Ambiguous,
            } => self.ambiguous += 1,
            GroundTruth::Contextual { relation } => {
                self.contextual_rows += 1;
                if row.coverage == CoverageState::Completed
                    && matches!(
                        row.normalized,
                        Some(NormalizedDecision::ContextualAlignment { relation: observed })
                            if observed == relation
                    )
                {
                    self.contextual_correct += 1;
                }
            }
        }
    }
}
