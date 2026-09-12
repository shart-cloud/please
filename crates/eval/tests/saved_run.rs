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
