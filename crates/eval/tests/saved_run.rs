//! Test the same run interface as the commands, using small local rows and real filesystem writes.
use clap::Parser;
use please_core::{Engine, RiskLevel};
use please_eval::product::{ProductOptions, Runtime};
use please_eval::rows::Row;
use please_eval::run::{self, EvaluationRun, RunStatus};
use please_eval::slice::{Origin, SliceSet};
use serde_json::Value;
use std::{fs, path::Path};

#[derive(Parser)]
struct Options {
    #[command(flatten)]
    pipeline: ProductOptions,
}

fn runtime() -> Runtime {
    Options::parse_from(["test", "--mode", "mechanism"])
        .pipeline
        .resolve(RiskLevel::Low)
        .unwrap()
}

fn corpus() -> SliceSet {
    let mut set = SliceSet::load().unwrap();
    let mut local = set.get("fix_benign").unwrap().clone();
    local.baseline_permille = Some(0);
    let mut remote = local.clone();
    remote.id = "remote_benign".into();
    remote.origin = Origin::Query {
        sql: "test-only query; no acquisition".into(),
    };
    set.slices = vec![local, remote];
    set
}

fn rows() -> Vec<Row> {
    vec![
        Row::new("one", "test", "Ordinary garden notes."),
        Row::new("two", "test", "Rain tomorrow."),
    ]
}

fn complete(root: &Path) {
    let engine = Engine::builtin().unwrap();
    let runtime = runtime();
    let mut run =
        EvaluationRun::create(root, "saved", &runtime, &engine, "builtin", corpus()).unwrap();
    for id in ["fix_benign", "remote_benign"] {
        run.scan_slice(id, &rows()).unwrap();
    }
    run.finish().unwrap();
}

#[test]
fn selection_is_recorded_before_scanning_and_every_interruption_remains_incomplete() {
    for saved in 0..=2 {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::builtin().unwrap();
        let runtime = runtime();
        let mut run =
            EvaluationRun::create(dir.path(), "saved", &runtime, &engine, "builtin", corpus())
                .unwrap();
        let initial = run::report(dir.path(), "saved", false).unwrap();
        assert_eq!(initial.gate.run_integrity.status(), RunStatus::Incomplete);
        assert_eq!(initial.to_json()["integrity"]["expected_slices"], 2);
        assert!(initial.metrics.is_empty());
        for id in ["fix_benign", "remote_benign"].into_iter().take(saved) {
            run.scan_slice(id, &rows()).unwrap();
        }
        // Even when every slice was published, a crash before finish does not establish completion.
        drop(run);
        fs::write(
            dir.path().join("saved/.remote_benign.jsonl.pending"),
            "partial write",
        )
        .unwrap();
        let partial = run::report(dir.path(), "saved", false).unwrap();
        assert_eq!(partial.metrics.len(), saved);
        assert_eq!(partial.gate.run_integrity.status(), RunStatus::Incomplete);
        assert!(partial.gate.failed(false, true));
    }
}

#[test]
fn cannot_finish_with_missing_slices_or_scan_unselected_or_duplicate_slices() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::builtin().unwrap();
    let runtime = runtime();
    let mut run =
        EvaluationRun::create(dir.path(), "saved", &runtime, &engine, "builtin", corpus()).unwrap();
    assert!(run.scan_slice("unselected", &rows()).is_err());
    run.scan_slice("fix_benign", &rows()).unwrap();
    assert!(run.scan_slice("fix_benign", &rows()).is_err());
    assert!(run.finish().is_err());
    assert!(run::report(dir.path(), "saved", false)
        .unwrap()
        .gate
        .failed(false, true));
}

#[test]
fn failed_publication_cannot_create_a_completion_record() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::builtin().unwrap();
    let runtime = runtime();
    let mut run =
        EvaluationRun::create(dir.path(), "saved", &runtime, &engine, "builtin", corpus()).unwrap();
    // Force rename failure after writing the complete temporary file.
    fs::create_dir(dir.path().join("saved/fix_benign.jsonl")).unwrap();
    assert!(run.scan_slice("fix_benign", &rows()).is_err());
    drop(run);
    let report = run::report(dir.path(), "saved", false).unwrap();
    assert!(report.metrics.is_empty());
    assert_eq!(report.gate.run_integrity.status(), RunStatus::Incomplete);
    assert!(report.gate.failed(false, true));
}

#[test]
fn corpus_publication_preserves_existing_pending_files() {
    for name in [".run.json.pending", ".fix_benign.jsonl.pending"] {
        let dir = tempfile::tempdir().unwrap();
        let engine = Engine::builtin().unwrap();
        let runtime = runtime();
        let mut run =
            EvaluationRun::create(dir.path(), "saved", &runtime, &engine, "builtin", corpus())
                .unwrap();
        let directory = dir.path().join("saved");
        let manifest = fs::read(directory.join("run.json")).unwrap();
        let pending = directory.join(name);
        fs::write(&pending, b"interrupted publication; retain these bytes").unwrap();

        assert!(run.scan_slice("fix_benign", &rows()).is_err(), "{name}");
        assert_eq!(
            fs::read(&pending).unwrap(),
            b"interrupted publication; retain these bytes"
        );
        assert_eq!(fs::read(directory.join("run.json")).unwrap(), manifest);
        let report = run::report(dir.path(), "saved", false).unwrap();
        assert_eq!(report.gate.run_integrity.status(), RunStatus::Incomplete);
        assert!(report.metrics.is_empty());
        assert!(report.gate.failed(false, true));
    }
}

#[test]
fn offline_view_never_hides_missing_public_corpus_results_from_the_gate() {
    let dir = tempfile::tempdir().unwrap();
    complete(dir.path());
    let report = run::report(dir.path(), "saved", true).unwrap();
    assert!(report.gate.run_integrity.is_complete());
    assert!(!report.gate.failed(false, false));
    assert_eq!(report.metrics.len(), 1);
    assert_eq!(report.gate.slices.len(), 2);
    fs::remove_file(dir.path().join("saved/remote_benign.jsonl")).unwrap();
    let report = run::report(dir.path(), "saved", true).unwrap();
    assert_eq!(report.metrics.len(), 1);
    assert!(report.gate.failed(false, true));
    assert!(report
        .gate
        .run_integrity
        .issues()
        .iter()
        .any(|i| i.slice.as_deref() == Some("remote_benign")));
}

#[test]
fn metadata_damage_unknown_versions_and_inconsistent_records_are_unverified() {
    for damage in [
        "metadata",
        "selection",
        "version",
        "missing_entry",
        "malformed",
    ] {
        let dir = tempfile::tempdir().unwrap();
        complete(dir.path());
        let path = dir.path().join("saved/run.json");
        let mut metadata: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        match damage {
            "metadata" => metadata["policy"]["threshold"] = Value::from("critical"),
            "selection" => {
                metadata["completion"]["corpus"]["slice"][0]["baseline_permille"] =
                    Value::from(1000)
            }
            "version" => metadata["completion"]["version"] = Value::from(99),
            "missing_entry" => {
                metadata["completion"]["results"]
                    .as_object_mut()
                    .unwrap()
                    .remove("remote_benign");
            }
            "malformed" => {}
            _ => unreachable!(),
        }
        fs::write(
            &path,
            if damage == "malformed" {
                b"{broken".to_vec()
            } else {
                serde_json::to_vec(&metadata).unwrap()
            },
        )
        .unwrap();
        let report = run::report(dir.path(), "saved", false).unwrap();
        assert_eq!(
            report.gate.run_integrity.status(),
            RunStatus::Unverified,
            "{damage}"
        );
        assert!(report.gate.failed(false, true));
    }
}

#[test]
fn row_count_is_verified_even_when_saved_bytes_match_the_recorded_digest() {
    let dir = tempfile::tempdir().unwrap();
    complete(dir.path());
    let path = dir.path().join("saved/run.json");
    let mut metadata: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    metadata["completion"]["results"]["fix_benign"]["rows"] = Value::from(3);
    fs::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
    let report = run::report(dir.path(), "saved", false).unwrap();
    assert_eq!(report.gate.run_integrity.status(), RunStatus::Incomplete);
    assert!(report
        .gate
        .run_integrity
        .issues()
        .iter()
        .any(|i| i.detail.contains("expected 3")));
}

#[test]
fn reporting_uses_saved_slice_definitions_without_rereading_input_or_creating_directories() {
    let dir = tempfile::tempdir().unwrap();
    complete(dir.path());
    let before = fs::read(dir.path().join("saved/run.json")).unwrap();
    let report = run::report(dir.path(), "saved", false).unwrap();
    assert_eq!(report.gate.slices[0].baseline, Some(0)); // current fix_benign baseline is 50
    assert_eq!(report.gate.slices[1].slice_id, "remote_benign"); // absent from current corpus
    assert_eq!(fs::read(dir.path().join("saved/run.json")).unwrap(), before);
    assert!(run::report(&dir.path().join("absent"), "saved", false).is_err());
    assert!(!dir.path().join("absent").exists());
}

#[test]
fn empty_duplicate_or_unsafe_selections_are_refused_before_publication() {
    let dir = tempfile::tempdir().unwrap();
    let engine = Engine::builtin().unwrap();
    let runtime = runtime();
    for problem in ["empty", "duplicate", "unsafe"] {
        let mut set = corpus();
        match problem {
            "empty" => set.slices.clear(),
            "duplicate" => set.slices.push(set.slices[0].clone()),
            "unsafe" => set.slices[0].id = "../outside".into(),
            _ => unreachable!(),
        }
        assert!(
            EvaluationRun::create(dir.path(), problem, &runtime, &engine, "builtin", set).is_err()
        );
        assert!(!dir.path().join(problem).exists());
    }
}

#[test]
fn corpus_views_preserve_integrity_and_saved_bundle() {
    let dir = tempfile::tempdir().unwrap();
    complete(dir.path());
    let report = run::report(dir.path(), "saved", false).unwrap();
    let destination = dir.path().join("saved");
    please_eval::corpus_presentation::save_bundle(&report, &destination).unwrap();
    let html = fs::read_to_string(destination.join("report.html")).unwrap();
    assert!(html.contains("Saved results: COMPLETE"));
    assert!(html.contains("Default regression gate: PASSED"));
    assert!(html.contains("remote_benign"));
    let json: Value =
        serde_json::from_slice(&fs::read(destination.join("report.json")).unwrap()).unwrap();
    assert_eq!(json, report.to_json());
    fs::write(destination.join("remote_benign.jsonl"), "corrupt").unwrap();
    let damaged = run::report(dir.path(), "saved", false).unwrap();
    let rendered = please_eval::corpus_presentation::render_html(&damaged);
    assert!(rendered.contains("Saved results: INCOMPLETE"));
    assert!(rendered.contains("Default regression gate: FAILED"));
}

#[test]
fn corpus_cli_automatically_saves_reports_and_exports_saved_results() {
    let cache = tempfile::tempdir().unwrap();
    let command = || {
        let mut cmd = std::process::Command::new(env!("CARGO_BIN_EXE_please-eval"));
        cmd.env("PLEASE_EVAL_CACHE", cache.path());
        cmd
    };
    let result = command()
        .args(["run", "--slice", "fix_benign", "--run", "presentation-cli"])
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let run = cache.path().join("results/presentation-cli");
    for name in ["report.html", "report.json", "report.md", "run.json"] {
        assert!(run.join(name).is_file());
    }
    let result = command()
        .args(["report", "--run", "presentation-cli", "--format", "html"])
        .output()
        .unwrap();
    assert!(result.status.success());
    assert!(String::from_utf8_lossy(&result.stdout).contains("Saved results: COMPLETE"));
    let result = command()
        .args(["view", "--run", "presentation-cli"])
        .output()
        .unwrap();
    assert!(!result.status.success());
    assert!(String::from_utf8_lossy(&result.stderr).contains("require terminal"));
}

#[test]
fn overlapping_coverage_causes_count_each_row_once() {
    let dir = tempfile::tempdir().unwrap();
    complete(dir.path());
    let data = fs::read_to_string(dir.path().join("saved/fix_benign.jsonl")).unwrap();
    let mut row: please_eval::rows::RowResult =
        serde_json::from_str(data.lines().next().unwrap()).unwrap();
    row.incomplete = vec!["decode_depth".into(), "max_matches_per_rule".into()];
    let set = corpus();
    let metric =
        please_eval::metrics::SliceMetrics::compute(set.get("fix_benign").unwrap(), &[row]);
    assert_eq!(metric.incomplete_rows, 1);
    assert_eq!(metric.incomplete.values().sum::<u64>(), 2);
    let mut report = run::report(dir.path(), "saved", false).unwrap();
    report.metrics = vec![metric];
    assert!(report
        .known_gaps()
        .iter()
        .any(|s| s.contains("1 distinct rows")));
    assert_eq!(report.to_json()["slices"][0]["incomplete_rows"], 1);
}
