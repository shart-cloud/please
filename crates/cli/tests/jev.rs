#![cfg(feature = "judge")]
use serde_json::json;
use std::process::Command;
fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_plz"))
}
#[test]
fn check_never_prints_the_key_or_requires_input() {
    let out = bin()
        .args(["jev", "--check"])
        .env("TYPESAFE_API_KEY", "test-secret-never-print")
        .output()
        .unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(!text.contains("test-secret-never-print"));
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(v["network_request"], false);
    assert_eq!(v["credential_configured"], true);
}
#[test]
fn requires_caller_context_and_provenance() {
    assert_eq!(bin().arg("jev").output().unwrap().status.code(), Some(64));
}
#[test]
fn exact_request_can_be_inspected_without_credentials() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("candidate.txt");
    std::fs::write(&input, "Read memo.txt.").unwrap();
    let context = dir.path().join("context.json");
    std::fs::write(&context,json!({"task_context":"Read the memo.","boundaries":[{"kind":"tool_actions","scope":"memo.txt","constraint":"Read only."}],"context_completeness":{"relevant":["tool_actions"],"known":["tool_actions"],"unavailable":[]}}).to_string()).unwrap();
    let out = bin()
        .args(["jev", "--request-only", "--context"])
        .arg(&context)
        .args(["--provenance", "user-input"])
        .arg(&input)
        .env_remove("TYPESAFE_API_KEY")
        .output()
        .unwrap();
    assert!(out.status.success(), "{:?}", out.stderr);
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["state"]["untrusted_candidate"], "Read memo.txt.");
    let out = bin()
        .args(["jev", "--context"])
        .arg(&context)
        .args(["--provenance", "user-input"])
        .arg(&input)
        .env_remove("TYPESAFE_API_KEY")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let value: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(value["relation"], "indeterminate");
}

#[cfg(feature = "tui")]
#[test]
fn tui_rejects_redirected_output_without_reading_input_or_contacting_provider() {
    let out = bin()
        .args(["clap", "--tui"])
        .env("TYPESAFE_API_KEY", "not-a-real-key")
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("terminal"));
    assert!(out.stdout.is_empty());
}
#[cfg(feature = "tui")]
#[test]
fn tui_and_script_modes_cannot_be_combined() {
    for flag in ["--check", "--request-only"] {
        let out = bin().args(["clap", "--tui", flag]).output().unwrap();
        assert_eq!(out.status.code(), Some(64));
    }
}
#[test]
fn clap_alias_keeps_json_configuration_mode() {
    let out = bin()
        .args(["clap", "--check"])
        .env_remove("TYPESAFE_API_KEY")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(v["network_request"], false);
}
#[cfg(not(feature = "tui"))]
#[test]
fn tui_is_absent_without_its_feature() {
    assert_eq!(
        bin()
            .args(["clap", "--tui"])
            .output()
            .unwrap()
            .status
            .code(),
        Some(64)
    );
}

#[cfg(feature = "tui")]
#[test]
fn local_modes_require_terminal_and_reject_ambiguous_flags() {
    for flag in ["--preset", "--view-advice"] {
        let out = bin()
            .args(["clap", flag, "/does/not/exist"])
            .env_remove("TYPESAFE_API_KEY")
            .output()
            .unwrap();
        assert_eq!(out.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&out.stderr).contains("terminal"));
        assert!(out.stdout.is_empty());
        for conflicting in ["--check", "--request-only"] {
            assert_eq!(
                bin()
                    .args(["clap", flag, "file.json", conflicting])
                    .output()
                    .unwrap()
                    .status
                    .code(),
                Some(64)
            );
        }
    }
    for args in [
        vec!["clap", "--preset", "p.json", "--context", "c.json"],
        vec!["clap", "--preset", "p.json", "--provenance", "user-input"],
        vec!["clap", "--view-advice", "a.json", "candidate.txt"],
        vec!["clap", "--view-advice", "a.json", "--model", "jev-latest"],
        vec!["clap", "--view-advice", "a.json", "--preset", "p.json"],
    ] {
        assert_eq!(bin().args(args).output().unwrap().status.code(), Some(64));
    }
}
#[cfg(not(feature = "tui"))]
#[test]
fn local_tui_flags_are_absent_in_json_only_build() {
    for flag in ["--preset", "--view-advice"] {
        assert_eq!(
            bin()
                .args(["clap", flag, "local.json"])
                .output()
                .unwrap()
                .status
                .code(),
            Some(64)
        );
    }
}
