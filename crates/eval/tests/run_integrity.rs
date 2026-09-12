use serde_json::Value;
use std::{fs, path::Path, process::Command};

fn command(cache: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_please-eval"))
        .env("PLEASE_EVAL_CACHE", cache)
        .args(args)
        .output()
        .unwrap()
}

fn create(cache: &Path) {
    let output = command(
        cache,
        &[
            "run",
            "--offline",
            "--mode",
            "mechanism",
            "--run",
            "integrity",
            "--slice",
            "fix_benign",
            "--slice",
            "repo_prose",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn report(cache: &Path) -> Value {
    let output = command(
        cache,
        &[
            "report",
            "--offline",
            "--run",
            "integrity",
            "--format",
            "json",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn corrupt_missing_truncated_and_modified_slices_cannot_disappear_into_a_passing_gate() {
    for mutation in ["malformed", "missing", "truncated", "modified"] {
        let cache = tempfile::tempdir().unwrap();
        create(cache.path());
        assert_eq!(report(cache.path())["slices"].as_array().unwrap().len(), 2);
        assert!(
            command(cache.path(), &["gate", "--offline", "--run", "integrity"])
                .status
                .success()
        );
        let path = cache.path().join("results/integrity/fix_benign.jsonl");
        let original = fs::read_to_string(&path).unwrap();
        match mutation {
            "malformed" => fs::write(&path, "{broken json}\n").unwrap(),
            "missing" => fs::remove_file(&path).unwrap(),
            "truncated" => {
                fs::write(&path, format!("{}\n", original.lines().next().unwrap())).unwrap()
            }
            "modified" => {
                let mut rows: Vec<Value> = original
                    .lines()
                    .map(|l| serde_json::from_str(l).unwrap())
                    .collect();
                rows[0]["score"] = serde_json::json!(99);
                fs::write(
                    &path,
                    rows.iter().map(|r| format!("{r}\n")).collect::<String>(),
                )
                .unwrap();
            }
            _ => unreachable!(),
        }
        assert_eq!(
            command(cache.path(), &["gate", "--offline", "--run", "integrity"])
                .status
                .code(),
            Some(2),
            "{mutation}: damaged run must fail"
        );
        let partial = report(cache.path());
        assert_eq!(
            partial["integrity"]["status"], "incomplete",
            "{mutation}: {partial}"
        );
        assert!(partial["integrity"]["issues"]
            .as_array()
            .unwrap()
            .iter()
            .any(|i| i["slice"] == "fix_benign"));
        assert_eq!(partial["slices"].as_array().unwrap().len(), 1);
        assert_eq!(partial["slices"][0]["slice"], "repo_prose");
        for extra in [
            vec![],
            vec!["--allow-unpinned"],
            vec!["--strict", "--allow-unpinned"],
        ] {
            let mut args = vec!["gate", "--offline", "--run", "integrity"];
            args.extend(extra);
            let gate = command(cache.path(), &args);
            assert_eq!(gate.status.code(), Some(2), "{mutation}");
            assert!(String::from_utf8_lossy(&gate.stderr).contains("rerun"));
        }
        let markdown = command(cache.path(), &["report", "--offline", "--run", "integrity"]);
        assert!(String::from_utf8_lossy(&markdown.stdout).contains("INCOMPLETE"));
    }
}

#[test]
fn old_or_missing_completion_records_require_a_rerun_even_with_readable_results() {
    for missing_metadata in [false, true] {
        let cache = tempfile::tempdir().unwrap();
        create(cache.path());
        let path = cache.path().join("results/integrity/run.json");
        if missing_metadata {
            fs::remove_file(path).unwrap();
        } else {
            let mut metadata: Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            metadata.as_object_mut().unwrap().remove("completion");
            fs::write(path, serde_json::to_vec(&metadata).unwrap()).unwrap();
        }
        let legacy = report(cache.path());
        assert_eq!(legacy["integrity"]["status"], "unverified");
        assert_eq!(
            command(
                cache.path(),
                &[
                    "gate",
                    "--offline",
                    "--run",
                    "integrity",
                    "--allow-unpinned"
                ]
            )
            .status
            .code(),
            Some(2)
        );
    }
}

#[test]
fn an_existing_run_cannot_be_extended_or_overwritten() {
    let cache = tempfile::tempdir().unwrap();
    create(cache.path());
    let path = cache.path().join("results/integrity/run.json");
    let original = fs::read(&path).unwrap();
    for slice in ["fix_benign", "fix_positive"] {
        let output = command(
            cache.path(),
            &[
                "run",
                "--offline",
                "--mode",
                "mechanism",
                "--run",
                "integrity",
                "--slice",
                slice,
            ],
        );
        assert!(!output.status.success());
        assert!(String::from_utf8_lossy(&output.stderr).contains("new --run label"));
        assert_eq!(fs::read(&path).unwrap(), original);
    }
}

#[test]
fn failed_input_acquisition_leaves_the_full_selection_visible_and_fails_the_gate() {
    let cache = tempfile::tempdir().unwrap();
    // The second slice has no cached input. Acquisition is cache-only; no fetch is requested.
    let output = command(
        cache.path(),
        &[
            "run",
            "--mode",
            "mechanism",
            "--run",
            "integrity",
            "--slice",
            "fix_benign",
            "--slice",
            "neg_orbench",
        ],
    );
    assert!(!output.status.success());
    let partial = report(cache.path());
    assert_eq!(partial["integrity"]["status"], "incomplete");
    assert_eq!(partial["integrity"]["expected_slices"], 2);
    assert_eq!(partial["integrity"]["verified_slices"], 1);
    assert!(partial["integrity"]["issues"]
        .as_array()
        .unwrap()
        .iter()
        .any(|i| i["slice"] == "neg_orbench"));
    assert_eq!(
        command(
            cache.path(),
            &[
                "gate",
                "--offline",
                "--run",
                "integrity",
                "--allow-unpinned"
            ]
        )
        .status
        .code(),
        Some(2)
    );
}
