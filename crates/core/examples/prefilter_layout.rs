//! Diagnostic reconstruction of the production prefilter builder; no shipping override.
use aho_corasick::{AhoCorasickBuilder, MatchKind};
use please_core::Engine;
use std::{fs, io::Write};
fn main() {
    let args: Vec<_> = std::env::args().collect();
    assert_eq!(args.len(), 3, "CONFIGS.json OUTPUT.json");
    let configs: serde_json::Value = serde_json::from_slice(&fs::read(&args[1]).unwrap()).unwrap();
    let mut result = serde_json::Map::new();
    for c in configs.as_array().unwrap() {
        let source = fs::read_to_string(c["source"].as_str().unwrap()).unwrap();
        let engine = Engine::from_toml(&source).unwrap();
        let mut literals = Vec::new();
        for rule in engine.ruleset().all_rules() {
            if !rule.enabled {
                continue;
            }
            for literal in &rule.literals {
                if !literals.contains(&literal.as_str()) {
                    literals.push(literal.as_str());
                }
            }
        }
        let matcher = AhoCorasickBuilder::new()
            .ascii_case_insensitive(true)
            .match_kind(MatchKind::Standard)
            .build(&literals)
            .unwrap();
        result.insert(c["label"].as_str().unwrap().to_owned(),serde_json::json!({
            "distinct_literals":literals.len(),"kind":format!("{:?}",matcher.kind()),"memory_bytes":matcher.memory_usage()
        }));
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[2])
        .unwrap();
    f.write_all(&serde_json::to_vec_pretty(&result).unwrap())
        .unwrap();
}
