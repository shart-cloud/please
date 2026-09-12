use std::path::{Path, PathBuf};

use please_eval::{capture, replay};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

fn setup(dir: &Path) -> (PathBuf, Vec<PathBuf>, Value) {
    let mut cases = Vec::new();
    for (index, source) in [
        "untrusted_user_input",
        "untrusted_tool_response",
        "security_reference",
        "untrusted_user_input",
    ]
    .iter()
    .enumerate()
    {
        let bytes = format!("synthetic instrument test {index}\r\n\0\u{feff}").into_bytes();
        let name = format!("input-{index}.bin");
        std::fs::write(dir.join(&name), &bytes).unwrap();
        cases.push(json!({
            "capture": {
                "id": format!("case-{index}"), "input_path": name, "input_sha256": hash(&bytes),
                "source": source, "control_role": "test",
                "label": if index == 3 { "injection" } else { "benign" },
                "label_reason": "Synthetic test label; no measured detection claim."
            },
            "group": format!("group-{index}"), "split": "holdout", "provenance": "synthetic test",
            "task_context": "Test the instrument", "labeler": "test fixture", "previously_exposed": false
        }));
    }
    let draft = json!({
        "format_version": 1, "collection_id": "synthetic-test", "owner": "test fixture",
        "reviewed_at": "2026-09-11T00:00:00Z", "protocol": "Synthetic instrument validation only",
        "cases": cases
    });
    let path = dir.join("draft.json");
    save(&path, &draft);
    let exclusion = dir.join("exposed.jsonl");
    std::fs::write(&exclusion, "{\"text\":\"previously exposed bytes\"}\n").unwrap();
    (path, vec![exclusion], draft)
}

fn save(path: &Path, value: &Value) {
    std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

#[test]
fn freeze_preserves_bytes_and_feeds_the_existing_replay_join() {
    let dir = tempfile::tempdir().unwrap();
    let (draft, exclusions, original) = setup(dir.path());
    let out = dir.path().join("frozen");
    let digest = capture::freeze(&draft, &exclusions, &out).unwrap();
    capture::check(&out, &digest).unwrap();
    assert!(capture::freeze(&draft, &exclusions, &out).is_err());
    let manifest = out.join("holdout/captures.jsonl");
    let captures: Vec<replay::Capture> = std::fs::read_to_string(&manifest)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let mut baseline = String::new();
    for (index, case) in captures.iter().enumerate() {
        assert_eq!(
            std::fs::read(out.join("holdout").join(&case.input_path)).unwrap(),
            std::fs::read(
                dir.path().join(
                    original["cases"][index]["capture"]["input_path"]
                        .as_str()
                        .unwrap()
                )
            )
            .unwrap()
        );
        baseline.push_str(&json!({
            "id": case.id, "input_sha256": case.input_sha256, "source": case.source,
            "control_role": case.control_role,
            "scanner": { "name": "synthetic", "version": "1", "configuration": { "fixture": true } },
            "decision": "allow", "reasons": [], "incomplete": false, "error": null
        }).to_string());
        baseline.push('\n');
    }
    let baseline_path = dir.path().join("baseline.jsonl");
    std::fs::write(&baseline_path, baseline).unwrap();
    assert_eq!(replay::compare(&manifest, &baseline_path).unwrap().len(), 4);
    // Original capture mutation cannot silently mutate the frozen snapshot.
    std::fs::write(dir.path().join("input-0.bin"), b"changed original").unwrap();
    capture::check(&out, &digest).unwrap();
    std::fs::write(out.join("holdout/inputs/0000.bin"), b"changed frozen").unwrap();
    assert!(capture::check(&out, &digest).is_err());
    // Updating the colocated hashes still cannot defeat the separately retained digest.
    let freeze_path = out.join("freeze.json");
    let mut freeze: Value = serde_json::from_slice(&std::fs::read(&freeze_path).unwrap()).unwrap();
    freeze["files"]["holdout/inputs/0000.bin"] = json!(hash(b"changed frozen"));
    save(&freeze_path, &freeze);
    assert!(capture::check(&out, &digest)
        .unwrap_err()
        .to_string()
        .contains("separately retained"));
}

#[test]
fn invalid_evidence_never_creates_a_bundle() {
    for mutation in [
        "unreviewed",
        "exposed",
        "bytes",
        "duplicate",
        "source",
        "coverage",
        "group",
        "content_split",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (draft, exclusions, mut value) = setup(dir.path());
        match mutation {
            "unreviewed" => value["cases"][0]["labeler"] = json!(""),
            "exposed" => value["cases"][0]["previously_exposed"] = json!(true),
            "bytes" => {
                std::fs::write(dir.path().join("input-0.bin"), b"changed").unwrap();
            }
            "duplicate" => {
                value["cases"][1]["capture"]["id"] = value["cases"][0]["capture"]["id"].clone()
            }
            "source" => value["cases"][0]["capture"]["source"] = json!("unspecified"),
            "coverage" => value["cases"][2]["capture"]["label"] = json!("uncertain"),
            "group" | "content_split" => {
                let mut extra = value["cases"][0].clone();
                extra["capture"]["id"] = json!("development-case");
                extra["capture"]["control_role"] = json!("other-role");
                extra["split"] = json!("development");
                if mutation == "content_split" {
                    extra["group"] = json!("different-group");
                }
                value["cases"].as_array_mut().unwrap().push(extra);
            }
            _ => unreachable!(),
        }
        save(&draft, &value);
        let out = dir.path().join("frozen");
        assert!(
            capture::freeze(&draft, &exclusions, &out).is_err(),
            "{mutation}"
        );
        assert!(!out.exists(), "{mutation}");
    }
}

#[test]
fn both_prior_capture_hashes_and_authored_text_exclude_holdout_rows() {
    for by_hash in [true, false] {
        let dir = tempfile::tempdir().unwrap();
        let (draft, exclusions, value) = setup(dir.path());
        let row = if by_hash {
            json!({ "input_sha256": value["cases"][0]["capture"]["input_sha256"] })
        } else {
            json!({ "text": std::fs::read_to_string(dir.path().join("input-0.bin")).unwrap() })
        };
        save(&exclusions[0], &row);
        assert!(
            capture::freeze(&draft, &exclusions, &dir.path().join("frozen"))
                .unwrap_err()
                .to_string()
                .contains("exposed capture")
        );
    }
}

#[test]
fn changed_labels_and_missing_files_fail_integrity_check() {
    for file in [
        "collection.json",
        "holdout/captures.jsonl",
        "known-exposed.json",
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (draft, exclusions, _) = setup(dir.path());
        let out = dir.path().join("frozen");
        let digest = capture::freeze(&draft, &exclusions, &out).unwrap();
        let original = std::fs::read(out.join(file)).unwrap();
        let edited = String::from_utf8(original.clone())
            .unwrap()
            .replace("benign", "injection");
        std::fs::write(out.join(file), edited + " ").unwrap();
        assert!(capture::check(&out, &digest).is_err());
        std::fs::write(out.join(file), original).unwrap();
        std::fs::remove_file(out.join(file)).unwrap();
        assert!(capture::check(&out, &digest).is_err());
    }
}

#[test]
fn arbitrary_bytes_and_permissions_are_snapshotted_and_verified() {
    let dir = tempfile::tempdir().unwrap();
    let (draft, exclusions, mut value) = setup(dir.path());
    let bytes = [0xff, 0x00, 0xc0, b'\r', b'\n'];
    std::fs::write(dir.path().join("input-0.bin"), bytes).unwrap();
    value["cases"][0]["capture"]["input_sha256"] = json!(hash(&bytes));
    let policy = std::fs::read(
        please_eval::repo_root()
            .unwrap()
            .join("examples/export-policy.toml"),
    )
    .unwrap();
    std::fs::write(dir.path().join("permissions.toml"), &policy).unwrap();
    value["export_policy_path"] = json!("permissions.toml");
    save(&draft, &value);
    let out = dir.path().join("frozen");
    let digest = capture::freeze(&draft, &exclusions, &out).unwrap();
    assert_eq!(
        std::fs::read(out.join("holdout/inputs/0000.bin")).unwrap(),
        bytes
    );
    assert_eq!(
        std::fs::read(out.join("export-policy.toml")).unwrap(),
        policy
    );
    capture::check(&out, &digest).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o077,
            0
        );
    }
    std::fs::write(out.join("export-policy.toml"), b"changed").unwrap();
    assert!(capture::check(&out, &digest).is_err());
}

#[test]
fn empty_or_malformed_exposure_history_cannot_claim_freshness() {
    for bytes in ["", "{}", "{\"input_sha256\":\"invalid\"}", "not json"] {
        let dir = tempfile::tempdir().unwrap();
        let (draft, exclusions, _) = setup(dir.path());
        std::fs::write(&exclusions[0], bytes).unwrap();
        let out = dir.path().join("frozen");
        assert!(capture::freeze(&draft, &exclusions, &out).is_err());
        assert!(!out.exists());
    }
}

#[test]
fn cli_requires_exposure_history_and_an_external_digest() {
    let binary = env!("CARGO_BIN_EXE_please-eval");
    for args in [
        vec!["capture", "freeze", "--draft", "unused", "--out", "unused"],
        vec!["capture", "check", "--dir", "unused"],
    ] {
        let output = std::process::Command::new(binary)
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)
            .unwrap()
            .contains("required"));
    }
}
