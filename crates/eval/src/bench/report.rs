use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::bench::identity::{display_text, hex_decode, sha256};
use crate::bench::model::{
    BenchResult, ContextRelation, CoverageState, GroundTruth, NormalizedDecision, OperatingPoint,
    ProcessTelemetry, Surface,
};
use crate::bench::runner::{verify_saved_run, RESULT_SCHEMA};
pub use crate::metrics::bench::{MetricCounts, RelationMatrix};
use crate::saved_run::SavedRun;
use crate::Result;

#[derive(Debug, Clone, Serialize)]
pub struct MetricRecord {
    pub system_id: String,
    pub surface: Surface,
    pub axis: String,
    pub value: String,
    pub counts: MetricCounts,
}

#[derive(Debug, Clone, Serialize)]
pub struct PairedChange {
    pub system_id: String,
    pub group_id: String,
    pub repetition: u32,
    pub case_a: String,
    pub case_b: String,
    pub expected_change: String,
    pub observed_change: Option<String>,
    pub correct_a: Option<bool>,
    pub correct_b: Option<bool>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SystemCard {
    pub system_id: String,
    pub system_digest: String,
    pub operating_point: OperatingPoint,
    pub adapter_version: String,
    pub normalizers: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct BenchReport {
    pub schema_version: String,
    pub run_id: String,
    pub pack_id: String,
    pub pack_digest: String,
    pub caveat: String,
    pub execution_posture: String,
    pub systems: Vec<SystemCard>,
    pub processes: Vec<ProcessTelemetry>,
    pub strata: Vec<MetricRecord>,
    pub contextual_matrix: Vec<RelationMatrix>,
    pub paired_changes: Vec<PairedChange>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ComparisonReport {
    pub schema_version: String,
    pub run_id: String,
    pub compared_rows: u64,
    pub changed_decisions: u64,
    pub changed_by_system: BTreeMap<String, u64>,
}

#[derive(Debug, Clone)]
struct PairDatum {
    case_id: String,
    expected: ContextRelation,
    observed: Option<ContextRelation>,
}

pub fn build(directory: &Path) -> Result<BenchReport> {
    let run = verify_saved_run(directory)?;
    let execution_posture = execution_posture(&run);
    let systems_by_digest: BTreeMap<_, _> = run
        .systems
        .iter()
        .map(|system| (system.system_digest.as_str(), system))
        .collect();
    let case_digests: BTreeSet<_> = run
        .ordered_case_digests
        .iter()
        .map(String::as_str)
        .collect();
    let mut seen = BTreeSet::new();
    let mut metrics: BTreeMap<(String, Surface, String, String), MetricCounts> = BTreeMap::new();
    let mut matrix: BTreeMap<(String, ContextRelation, ContextRelation), u64> = BTreeMap::new();
    let mut pairs: BTreeMap<(String, String, u32), Vec<PairDatum>> = BTreeMap::new();
    let storage = SavedRun::<BenchResult>::at(directory);
    for row in storage.rows("results.jsonl")? {
        let row = row?;
        validate_row(&run, &systems_by_digest, &case_digests, &mut seen, &row)?;
        for (axis, value) in row_axes(&row) {
            metrics
                .entry((row.system_id.clone(), row.surface, axis, value))
                .or_default()
                .add(&row);
        }
        if let (
            GroundTruth::Contextual { relation: expected },
            Some(NormalizedDecision::ContextualAlignment { relation: observed }),
        ) = (&row.ground_truth, &row.normalized)
        {
            if row.coverage == CoverageState::Completed {
                *matrix
                    .entry((row.system_id.clone(), *expected, *observed))
                    .or_default() += 1;
            }
            pairs
                .entry((row.system_id.clone(), row.group_id.clone(), row.repetition))
                .or_default()
                .push(PairDatum {
                    case_id: row.case_id.clone(),
                    expected: *expected,
                    observed: (row.coverage == CoverageState::Completed).then_some(*observed),
                });
        } else if let GroundTruth::Contextual { relation: expected } = &row.ground_truth {
            pairs
                .entry((row.system_id.clone(), row.group_id.clone(), row.repetition))
                .or_default()
                .push(PairDatum {
                    case_id: row.case_id.clone(),
                    expected: *expected,
                    observed: None,
                });
        }
    }
    let expected_rows =
        run.systems.len() as u64 * run.ordered_case_digests.len() as u64 * run.repetitions as u64;
    if seen.len() as u64 != expected_rows {
        return Err(format!(
            "run has {} unique rows; expected {expected_rows}",
            seen.len()
        )
        .into());
    }
    let strata = metrics
        .into_iter()
        .map(|((system_id, surface, axis, value), counts)| MetricRecord {
            system_id,
            surface,
            axis,
            value,
            counts,
        })
        .collect();
    const RELATIONS: [ContextRelation; 4] = [
        ContextRelation::AlignedInstruction,
        ContextRelation::ConflictingInstruction,
        ContextRelation::NonInstruction,
        ContextRelation::Indeterminate,
    ];
    let mut contextual_matrix = Vec::with_capacity(run.systems.len() * 16);
    for system in &run.systems {
        for expected in RELATIONS {
            for observed in RELATIONS {
                contextual_matrix.push(RelationMatrix {
                    system_id: system.system_id.clone(),
                    expected,
                    observed,
                    rows: *matrix
                        .get(&(system.system_id.clone(), expected, observed))
                        .unwrap_or(&0),
                });
            }
        }
    }
    let paired_changes = build_pairs(pairs, &run.group_baselines)?;
    let systems = run
        .systems
        .iter()
        .map(|system| SystemCard {
            system_id: system.system_id.clone(),
            system_digest: system.system_digest.clone(),
            operating_point: system.operating_point.clone(),
            adapter_version: system.adapter_version.clone(),
            normalizers: system
                .normalizers
                .iter()
                .map(|normalizer| format!("{}@{}", normalizer.normalizer_id, normalizer.version))
                .collect(),
        })
        .collect();
    Ok(BenchReport {
        schema_version: "please-bench-report/v1".into(),
        run_id: run.run_id,
        pack_id: run.pack_id,
        pack_digest: run.pack_digest,
        caveat: "Development, instrument, exposed, and same-author packs do not establish deployment accuracy or an independent holdout.".into(),
        execution_posture,
        systems,
        processes: run.processes,
        strata,
        contextual_matrix,
        paired_changes,
    })
}

fn execution_posture(run: &crate::bench::model::RunManifest) -> String {
    if run.execution_mode == crate::bench::model::ExecutionMode::NetworkAllowed {
        return "network allowed by experiment policy".into();
    }
    let subprocesses: Vec<_> = run
        .systems
        .iter()
        .filter_map(|system| system.sandbox_command.as_ref())
        .collect();
    if subprocesses.is_empty() {
        "declared offline; no subprocess systems were selected".into()
    } else if subprocesses.iter().all(|command| !command.is_empty()) {
        "declared offline; every subprocess used its manifest sandbox command".into()
    } else {
        "declared offline only; at least one subprocess ran without an OS network sandbox command"
            .into()
    }
}

fn validate_row<'a>(
    run: &crate::bench::model::RunManifest,
    systems: &BTreeMap<&'a str, &'a crate::bench::model::PlannedSystem>,
    cases: &BTreeSet<&str>,
    seen: &mut BTreeSet<String>,
    row: &BenchResult,
) -> Result<()> {
    if row.schema_version != RESULT_SCHEMA
        || row.run_id != run.run_id
        || row.pack_digest != run.pack_digest
        || !cases.contains(row.case_digest.as_str())
        || row.repetition >= run.repetitions
    {
        return Err(format!("row {} does not belong to the saved run", row.row_id).into());
    }
    crate::bench::identity::require_sha256(&row.input_sha256, "row input_sha256")?;
    crate::bench::identity::require_sha256(
        &row.normalized_input_sha256,
        "row normalized_input_sha256",
    )?;
    let system = systems
        .get(row.system_digest.as_str())
        .filter(|system| system.system_id == row.system_id)
        .ok_or("row system identity is not in the run plan")?;
    let expected_row_id = crate::bench::identity::canonical_digest(
        "please-bench-row/v1",
        &(row.request_id.as_str(), row.system_digest.as_str()),
    )?;
    if row.row_id != expected_row_id || !seen.insert(row.row_id.clone()) {
        return Err("row identity is invalid or duplicated".into());
    }
    let planned_normalizer = system
        .normalizers
        .iter()
        .find(|normalizer| normalizer.surface == row.surface);
    match planned_normalizer {
        Some(normalizer)
            if normalizer.normalizer_id == row.normalizer_id
                && normalizer.version == row.normalizer_version => {}
        None if row.coverage == CoverageState::Unsupported
            && row.normalizer_id == "unsupported" => {}
        _ => return Err("row normalizer identity is incompatible with the run plan".into()),
    }
    if row.coverage == CoverageState::Completed && row.normalized.is_none() {
        return Err("completed row has no normalized decision".into());
    }
    if row.coverage == CoverageState::Unsupported && row.normalized.is_some() {
        return Err("unsupported row has a normalized decision".into());
    }
    if let Some(raw) = &row.raw_output {
        if let Some(native) = &raw.native {
            if sha256(&serde_json::to_vec(native)?) != raw.native_sha256 {
                return Err("native output identity mismatch".into());
            }
        }
        validate_encoded_stream(
            raw.stdout_hex.as_deref(),
            raw.stdout_sha256.as_deref(),
            row.telemetry.stdout_bytes,
            "stdout",
        )?;
        validate_encoded_stream(
            raw.stderr_hex.as_deref(),
            raw.stderr_sha256.as_deref(),
            row.telemetry.stderr_bytes,
            "stderr",
        )?;
    }
    Ok(())
}

fn validate_encoded_stream(
    encoded: Option<&str>,
    digest: Option<&str>,
    length: u64,
    field: &str,
) -> Result<()> {
    match (encoded, digest, length) {
        (None, None, 0) => Ok(()),
        (Some(encoded), Some(digest), length) => {
            let bytes = hex_decode(encoded)?;
            if bytes.len() as u64 != length || sha256(&bytes) != digest {
                return Err(format!("{field} identity mismatch").into());
            }
            Ok(())
        }
        _ => Err(format!("{field} presence, digest, and length disagree").into()),
    }
}

fn row_axes(row: &BenchResult) -> Vec<(String, String)> {
    let mut axes = vec![
        ("surface".into(), row.surface.as_str().into()),
        ("source".into(), row.source.clone()),
        ("delivery_vector".into(), row.delivery_vector.clone()),
    ];
    if row.techniques.is_empty() {
        axes.push(("technique".into(), "none".into()));
    } else {
        axes.extend(
            row.techniques
                .iter()
                .cloned()
                .map(|technique| ("technique".into(), technique)),
        );
    }
    axes
}

fn build_pairs(
    groups: BTreeMap<(String, String, u32), Vec<PairDatum>>,
    baselines: &BTreeMap<String, String>,
) -> Result<Vec<PairedChange>> {
    let mut changes = Vec::new();
    for ((system_id, group_id, repetition), mut rows) in groups {
        rows.sort_by(|left, right| left.case_id.cmp(&right.case_id));
        if let Some(baseline_case_id) = baselines.get(&group_id) {
            let baseline = rows
                .iter()
                .find(|row| row.case_id == *baseline_case_id)
                .ok_or_else(|| {
                    format!(
                        "run baseline {baseline_case_id} is missing from contextual group {group_id}"
                    )
                })?;
            for row in rows.iter().filter(|row| row.case_id != *baseline_case_id) {
                changes.push(paired_change(
                    &system_id, &group_id, repetition, baseline, row,
                ));
            }
        } else {
            for (left_index, left) in rows.iter().enumerate() {
                for (right_index, right) in rows.iter().enumerate() {
                    if left_index != right_index {
                        changes.push(paired_change(
                            &system_id, &group_id, repetition, left, right,
                        ));
                    }
                }
            }
        }
    }
    Ok(changes)
}

fn paired_change(
    system_id: &str,
    group_id: &str,
    repetition: u32,
    left: &PairDatum,
    right: &PairDatum,
) -> PairedChange {
    PairedChange {
        system_id: system_id.into(),
        group_id: group_id.into(),
        repetition,
        case_a: left.case_id.clone(),
        case_b: right.case_id.clone(),
        expected_change: format!("{} -> {}", left.expected.as_str(), right.expected.as_str()),
        observed_change: left
            .observed
            .zip(right.observed)
            .map(|(a, b)| format!("{} -> {}", a.as_str(), b.as_str())),
        correct_a: left.observed.map(|observed| observed == left.expected),
        correct_b: right.observed.map(|observed| observed == right.expected),
    }
}

pub fn render_markdown(report: &BenchReport) -> String {
    let mut output = format!(
        "# Prompt-injection bench report\n\n- Run: `{}`\n- Pack: `{}` (`{}`)\n- Execution posture: {}\n- Caveat: {}\n\n## Systems and operating points\n\n| System | Adapter | Threshold | Description | Normalizers |\n|---|---|---|---|---|\n",
        md(&report.run_id),
        md(&report.pack_id),
        md(&report.pack_digest),
        md(&report.execution_posture),
        md(&report.caveat),
    );
    for system in &report.systems {
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} |\n",
            md(&system.system_id),
            md(&system.adapter_version),
            md(&system.operating_point.threshold),
            md(&system.operating_point.description),
            md(&system.normalizers.join(", ")),
        ));
    }
    output.push_str("\n## Subprocess diagnostics\n\n| System | Spawn | stderr bytes | Overflow | Exit | Runner terminated | stderr digest | Retained prefix |\n|---|---:|---:|---|---:|---|---|---|\n");
    if report.processes.is_empty() {
        output.push_str("| _none_ | 0 | 0 | no |  | no |  |  |\n");
    } else {
        for process in &report.processes {
            output.push_str(&format!(
                "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
                md(&process.system_id),
                process.spawn_index,
                process.stderr_bytes,
                if process.stderr_overflow { "yes" } else { "no" },
                process
                    .exit_status
                    .map(|status| status.to_string())
                    .unwrap_or_default(),
                if process.terminated_by_runner {
                    "yes"
                } else {
                    "no"
                },
                md(&process.stderr_sha256),
                md(&process.retained_stderr_hex),
            ));
        }
    }
    output.push_str("\n## Stratified results\n\n| System | Surface | Axis | Stratum | Rows | Complete | Unsupported | Fail/abstain | TP/FN | TN/FP | Context correct | Response time (µs) | Runner overhead (µs) |\n|---|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|\n");
    for record in &report.strata {
        let count = &record.counts;
        let failures = count.abstained
            + count.timeout
            + count.crashed
            + count.invalid_output
            + count.unavailable;
        output.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {}/{} | {}/{} | {}/{} | {} | {} |\n",
            md(&record.system_id),
            record.surface.as_str(),
            md(&record.axis),
            md(&record.value),
            count.rows,
            count.completed,
            count.unsupported,
            failures,
            count.true_positives,
            count.false_negatives,
            count.true_negatives,
            count.false_positives,
            count.contextual_correct,
            count.contextual_rows,
            count.elapsed_micros,
            count.runner_overhead_micros,
        ));
    }
    output.push_str("\n## Contextual relation matrix\n\n| System | Expected | Observed | Rows |\n|---|---|---|---:|\n");
    for cell in &report.contextual_matrix {
        output.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            md(&cell.system_id),
            cell.expected.as_str(),
            cell.observed.as_str(),
            cell.rows,
        ));
    }
    output.push_str("\n## Paired contextual changes\n\n| System | Group | Pair | Expected | Observed |\n|---|---|---|---|---|\n");
    for change in &report.paired_changes {
        output.push_str(&format!(
            "| {} | {} | {} → {} | {} | {} |\n",
            md(&change.system_id),
            md(&change.group_id),
            md(&change.case_a),
            md(&change.case_b),
            md(&change.expected_change),
            md(change.observed_change.as_deref().unwrap_or("unavailable")),
        ));
    }
    output
}

pub fn compare(left: &Path, right: &Path) -> Result<ComparisonReport> {
    let left_run = verify_saved_run(left)?;
    let right_run = verify_saved_run(right)?;
    if left_run.run_id != right_run.run_id
        || left_run.pack_digest != right_run.pack_digest
        || left_run.ordered_case_digests != right_run.ordered_case_digests
        || left_run.repetitions != right_run.repetitions
        || comparison_systems(&left_run)? != comparison_systems(&right_run)?
    {
        return Err(
            "bench runs have incompatible pack, system, normalizer, or operating-point identities"
                .into(),
        );
    }
    let left_rows = semantic_rows(left)?;
    let right_rows = semantic_rows(right)?;
    if left_rows.keys().collect::<Vec<_>>() != right_rows.keys().collect::<Vec<_>>() {
        return Err("bench runs do not contain the same row identities".into());
    }
    let mut changed = 0;
    let mut by_system = BTreeMap::new();
    for (row_id, left) in &left_rows {
        let right = &right_rows[row_id];
        if left != right {
            changed += 1;
            *by_system.entry(left.system_id.clone()).or_default() += 1;
        }
    }
    Ok(ComparisonReport {
        schema_version: "please-bench-comparison/v1".into(),
        run_id: left_run.run_id,
        compared_rows: left_rows.len() as u64,
        changed_decisions: changed,
        changed_by_system: by_system,
    })
}

fn comparison_systems(run: &crate::bench::model::RunManifest) -> Result<Vec<serde_json::Value>> {
    run.systems
        .iter()
        .map(|system| {
            Ok(serde_json::json!({
                "system_id": system.system_id,
                "system_digest": system.system_digest,
                "adapter_version": system.adapter_version,
                "normalizers": system.normalizers,
                "operating_point": system.operating_point,
                "runtime_identity": system.runtime_identity,
            }))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SemanticRow {
    system_id: String,
    coverage: CoverageState,
    normalized: Option<serde_json::Value>,
}

fn semantic_rows(directory: &Path) -> Result<BTreeMap<String, SemanticRow>> {
    let storage = SavedRun::<BenchResult>::at(directory);
    let mut rows = BTreeMap::new();
    for row in storage.rows("results.jsonl")? {
        let row = row?;
        let semantic = SemanticRow {
            system_id: row.system_id,
            coverage: row.coverage,
            normalized: row.normalized.map(serde_json::to_value).transpose()?,
        };
        if rows.insert(row.row_id, semantic).is_some() {
            return Err("duplicate row identity in results".into());
        }
    }
    Ok(rows)
}

fn md(value: &str) -> String {
    display_text(value).replace('|', "\\|")
}

pub fn write_report(directory: &Path, format: &str, out: Option<&Path>) -> Result<String> {
    let report = build(directory)?;
    let rendered = match format {
        "json" => format!("{}\n", serde_json::to_string_pretty(&report)?),
        "md" => render_markdown(&report),
        "html" => super::presentation::render_html(&report),
        "table" => super::presentation::render_table(&report),
        other => {
            return Err(format!(
                "unknown bench report format {other:?}; expected md, json, html, or table"
            )
            .into())
        }
    };
    if let Some(path) = out {
        std::fs::write(path, &rendered)?;
    }
    Ok(rendered)
}
