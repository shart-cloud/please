use serde_json::Value;
use std::{path::Path, process::Command};

fn run(cache: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_please-eval"))
        .env("PLEASE_EVAL_CACHE", cache)
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn product_measurement_matches_shipping_session_and_records_its_operating_point() {
    let cache = tempfile::tempdir().unwrap();
    let output = run(
        cache.path(),
        &[
            "run",
            "--offline",
            "--slice",
            "fix_benign",
            "--run",
            "product",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = cache.path().join("results/product");
    let metadata: Value =
        serde_json::from_slice(&std::fs::read(path.join("run.json")).unwrap()).unwrap();
    assert_eq!(metadata["mode"], "product");
    assert_eq!(metadata["policy"]["profile"], "enforcement");
    assert_eq!(metadata["policy"]["threshold"], "high");
    let engine = please_core::Engine::builtin().unwrap();
    let rows = please_eval::cases::read(please_eval::slice::LocalReader::FixturesBenign).unwrap();
    let expected = please_eval::scan::rows_with_session(
        &please_scan::ScanSession::new(&engine, please_core::ScanPolicy::default()),
        &rows,
    );
    let actual: Vec<Value> = std::fs::read_to_string(path.join("fix_benign.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(
        actual,
        expected
            .iter()
            .map(|r| serde_json::to_value(r).unwrap())
            .collect::<Vec<_>>()
    );
    let report = run(
        cache.path(),
        &[
            "report",
            "--offline",
            "--run",
            "product",
            "--format",
            "json",
        ],
    );
    assert!(report.status.success());
    let report: Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(report["floor"], "high");
    assert_eq!(report["ruleset_digest"], metadata["ruleset_digest"]);
    assert!(report["gate"]["slices"][0]["baseline_permille"].is_null());
    assert_eq!(report["gate"]["unpinned"][0], "fix_benign");
    let mismatch = run(
        cache.path(),
        &[
            "run",
            "--offline",
            "--slice",
            "fix_benign",
            "--run",
            "product",
            "--profile",
            "reference-analysis",
        ],
    );
    assert!(!mismatch.status.success());
    assert!(String::from_utf8_lossy(&mismatch.stderr).contains("different pipeline configuration"));
}

#[test]
fn mechanism_mode_keeps_its_explicit_historical_profile_and_baseline() {
    let cache = tempfile::tempdir().unwrap();
    let output = run(
        cache.path(),
        &[
            "run",
            "--offline",
            "--slice",
            "fix_benign",
            "--run",
            "historical",
            "--mode",
            "mechanism",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report = run(
        cache.path(),
        &[
            "report",
            "--offline",
            "--run",
            "historical",
            "--format",
            "json",
        ],
    );
    assert!(report.status.success());
    let report: Value = serde_json::from_slice(&report.stdout).unwrap();
    assert_eq!(report["floor"], "low");
    assert_eq!(report["gate"]["slices"][0]["baseline_permille"], 50);
}

#[cfg(feature = "shipping-ml")]
#[test]
fn product_can_measure_requested_but_unavailable_shipping_inference() {
    let cache = tempfile::tempdir().unwrap();
    let config = cache.path().join("model.json");
    std::fs::write(
        &config,
        serde_json::json!({"model_path":"missing-model", "model_id":"test",
        "revision":"test", "max_tokens":512, "malicious_label":1, "threshold":700})
        .to_string(),
    )
    .unwrap();
    let output = run(
        cache.path(),
        &[
            "run",
            "--offline",
            "--slice",
            "fix_benign",
            "--run",
            "missing-ml",
            "--ml-config",
            config.to_str().unwrap(),
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = cache.path().join("results/missing-ml");
    let metadata: Value =
        serde_json::from_slice(&std::fs::read(path.join("run.json")).unwrap()).unwrap();
    assert!(metadata["tiers"]["ml"]["unavailable"].is_string());
    for line in std::fs::read_to_string(path.join("fix_benign.jsonl"))
        .unwrap()
        .lines()
    {
        let value: Value = serde_json::from_str(line).unwrap();
        assert!(value["incomplete"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "tier_unavailable"));
    }
}
