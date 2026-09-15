//! Read-only diagnostic for frozen role-marker saturation review rows.
//! Does not change scan limits or rules. The diagnostic regex
//! iteration is independently capped at 129. An optional baseline rules path also
//! compares native gap details, allowing larger inputs with explicitly partial raw counts.
//! A third argument selects candidate rules explicitly instead of the built-in rules.
use please_core::structure::FrameMap;
use please_core::{Engine, ScanPolicy, TargetRef};

fn main() {
    let path = std::env::args().nth(1).expect("frozen package path");
    let baseline = std::env::args()
        .nth(2)
        .map(|path| Engine::from_toml(&std::fs::read_to_string(path).unwrap()).unwrap());
    let candidate = std::env::args().nth(3).map_or_else(
        || Engine::builtin().unwrap(),
        |path| Engine::from_toml(&std::fs::read_to_string(path).unwrap()).unwrap(),
    );
    let package: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    let rules: toml::Value = toml::from_str(include_str!("../../../rules/builtin.toml")).unwrap();
    let rule = rules["rule"]
        .as_array()
        .unwrap()
        .iter()
        .find(|rule| rule["id"].as_str() == Some("boundary.forged_role_marker"))
        .unwrap();
    let regex = regex::bytes::Regex::new(rule["pattern"].as_str().unwrap()).unwrap();
    for row in package["rows"]["pos_llmail"].as_array().unwrap() {
        let text = row["text"].as_str().unwrap().as_bytes();
        let frames = FrameMap::build(text);
        let matches: Vec<_> = regex.find_iter(text).take(129).collect();
        let diagnostic_limit_reached = matches.len() == 129;
        if baseline.is_none() {
            assert!(!diagnostic_limit_reached, "diagnostic limit reached");
        }
        let eligible: Vec<_> = matches
            .iter()
            .enumerate()
            .filter(|(_, m)| frames.is_frame(text, m.start()))
            .map(|(i, _)| i + 1)
            .collect();
        let lower = String::from_utf8_lossy(text).to_ascii_lowercase();
        // Historical gate must not silently become the current gate after a rule update.
        let old_gate = [
            "system:",
            "assistant:",
            "[system]",
            "<|im_start|>",
            "### system",
        ]
        .iter()
        .any(|literal| lower.contains(literal));
        let mut record = serde_json::json!({
                "id": row["id"], "bytes": text.len(),
                "raw_matches": (!diagnostic_limit_reached).then_some(matches.len()),
                "raw_matches_observed": matches.len(),
                "diagnostic_limit_reached": diagnostic_limit_reached,
            "eligible_match_ordinals": eligible,
            "eligible_within_cap": eligible.iter().filter(|i| **i <= 16).count(),
            "original_prefilter_admits": old_gate,
            "corrected_prefilter_admits": lower.contains("system") || lower.contains("assistant"),
            "production_match_cap": 16
        });
        if let Some(baseline) = &baseline {
            for (name, engine) in [("baseline", baseline), ("candidate", &candidate)] {
                let verdict =
                    engine.scan(text, &ScanPolicy::default(), TargetRef::stdin(text.len()));
                record[name] = serde_json::json!({
                    "score": verdict.score(),
                    "gaps": verdict.incomplete().iter().map(|g| serde_json::json!({
                        "cause": g.cause().as_str(), "configured": g.configured(), "detail": g.detail()
                    })).collect::<Vec<_>>()
                });
            }
        }
        println!("{record}");
    }
}
