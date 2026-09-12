use please_eval::scan::RuleSelection;
use please_scan::RuleLoadError;

#[test]
fn evaluation_uses_shared_acquisition_and_preserves_selection_provenance() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/rules/acme.toml");
    let selection = RuleSelection {
        rules: vec![path.clone()],
        disable: vec!["override.disregard_prior".into()],
    };
    let shared = please_scan::load_engine(&selection.rules, &selection.disable).unwrap();
    let evaluated = selection.engine().unwrap();
    assert_eq!(evaluated.ruleset_id(), shared.ruleset_id());
    assert_eq!(evaluated.warnings(), shared.warnings());
    assert_eq!(
        selection.describe(),
        format!("builtin +{} -override.disregard_prior", path.display())
    );

    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("later.toml");
    std::fs::write(&bad, "[ruleset").unwrap();
    let selection = RuleSelection {
        rules: vec![path, bad.clone()],
        disable: vec![],
    };
    let error = selection.engine().unwrap_err();
    assert!(
        matches!(error.downcast_ref::<RuleLoadError>(), Some(RuleLoadError::Parse { path, .. }) if path == &bad)
    );
}

#[test]
fn invalid_rules_abort_before_creating_an_evaluation_run() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing.toml");
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_please-eval"))
        .env("PLEASE_EVAL_CACHE", dir.path())
        .args([
            "run",
            "--offline",
            "--slice",
            "fix_benign",
            "--run",
            "invalid-rules",
            "--rules",
        ])
        .arg(&missing)
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains(&missing.display().to_string()));
    assert!(!dir.path().join("results/invalid-rules").exists());
}
