#![cfg(feature = "boundary")]
use please_eval::{boundary, replay::Label};
use serde_json::json;
use sha2::{Digest, Sha256};

fn fixture(dir: &std::path::Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let tokenizer = dir.join("tokenizer.json");
    // A tiny tokenizer artifact exercises the production planner; no weights or backend required.
    std::fs::write(&tokenizer, json!({"version":"1.0","truncation":null,"padding":null,
        "added_tokens":[],"normalizer":null,"pre_tokenizer":{"type":"Whitespace"},
        "post_processor":null,"decoder":null,
        "model":{"type":"WordLevel","vocab":{"[UNK]":0,"word":1,"attack":2,"now":3},"unk_token":"[UNK]"}}).to_string()).unwrap();
    std::fs::write(dir.join("input.txt"), "attack now").unwrap();
    let seeds = dir.join("seeds.json");
    std::fs::write(&seeds,json!([{"capture":{"id":"a","input_path":"input.txt",
        "input_sha256":format!("{:x}",Sha256::digest(b"attack now")),"source":"untrusted_tool_response",
        "control_role":"tool","label":"injection","label_reason":"synthetic fixture"},
        "group":"family-a","split":"development"}]).to_string()).unwrap();
    (seeds, tokenizer)
}
#[test]
fn generation_is_reproducible_and_verifies_realized_positions_and_hashes() {
    let temp = tempfile::tempdir().unwrap();
    let (seeds, tok) = fixture(temp.path());
    let a = temp.path().join("a");
    let b = temp.path().join("b");
    let digest = boundary::generate(&seeds, &tok, 8, &a).unwrap();
    assert_eq!(digest, boundary::generate(&seeds, &tok, 8, &b).unwrap());
    boundary::check(&a.join("suite.json"), &digest, &tok).unwrap();
    let suite: boundary::Suite =
        serde_json::from_slice(&std::fs::read(a.join("suite.json")).unwrap()).unwrap();
    assert_eq!(suite.cases.len(), 7);
    let crossing = suite
        .cases
        .iter()
        .find(|c| c.placement == "crossing")
        .unwrap();
    assert_eq!((crossing.token_start, crossing.token_end), (7, 9));
    assert!(suite
        .cases
        .iter()
        .all(|c| c.group == "family-a" && c.split == boundary::Split::Development));
    std::fs::write(a.join(&crossing.capture.input_path), "altered").unwrap();
    assert!(boundary::check(&a.join("suite.json"), &digest, &tok).is_err());
    assert!(boundary::generate(&seeds, &tok, 8, &a).is_err());
}
#[test]
fn split_leaks_and_unrealizable_placements_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let (seeds, tok) = fixture(temp.path());
    let mut rows: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&seeds).unwrap()).unwrap();
    let mut other = rows[0].clone();
    other["capture"]["id"] = json!("b");
    other["split"] = json!("holdout");
    rows.as_array_mut().unwrap().push(other);
    std::fs::write(&seeds, rows.to_string()).unwrap();
    assert!(boundary::generate(&seeds, &tok, 8, &temp.path().join("leak")).is_err());
    assert!(!temp.path().join("leak").exists());
}
#[test]
fn failures_remain_in_denominators_and_product_decisions_are_separate() {
    let mut counts = boundary::Counts::default();
    counts.record(Label::Injection, None, "review", true);
    counts.record(Label::Injection, Some(false), "block", false); // Structural tier can mask ML miss.
    counts.record(Label::Benign, Some(true), "block", false);
    counts.record(Label::Uncertain, None, "review", true);
    assert_eq!(
        (
            counts.total,
            counts.injections,
            counts.ml_hits,
            counts.ml_misses
        ),
        (4, 2, 0, 2)
    );
    assert_eq!(
        (counts.benign, counts.ml_false_positives, counts.incomplete),
        (1, 1, 2)
    );
}
