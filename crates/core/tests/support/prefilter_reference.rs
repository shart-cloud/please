//! Test/experiment-only reference. No production feature or engine setting bypasses the gate.
use please_core::{Engine, Verdict};

pub fn reference_source(source: &str) -> String {
    let mut document: toml::Value = toml::from_str(source).unwrap();
    for rule in document["rule"].as_array_mut().unwrap() {
        rule["literals"] = toml::Value::Array(Vec::new());
    }
    toml::to_string(&document).unwrap()
}

pub fn engines(source: &str) -> (Engine, Engine) {
    (
        Engine::from_toml(source).unwrap(),
        Engine::from_toml(&reference_source(source)).unwrap(),
    )
}

// Ruleset identities necessarily differ; behavior must not. This compares full
// observations (including transform chains), suppression, and per-rule gap details.
pub fn same_behavior(a: &Verdict, b: &Verdict) -> bool {
    a.score() == b.score()
        && a.risk() == b.risk()
        && a.outcome() == b.outcome()
        && a.analysis().reasons() == b.analysis().reasons()
        && a.analysis().suppressed() == b.analysis().suppressed()
        && a.incomplete() == b.incomplete()
}
