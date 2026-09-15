//! The reference changes literal admission only; no production bypass is introduced.
#[path = "support/prefilter_reference.rs"]
mod reference;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use please_core::{Engine, ScanPolicy, TargetRef};
use std::collections::BTreeSet;

const SOURCE: &str = include_str!("../../../rules/builtin.toml");

// Full gate corrections expose new benign findings for these five regexes.
// Keep their discrepancies visible; changing regex semantics is a separate task.
const DEFERRED: &[&str] = &[
    "solicitation.credentials",
    "solicitation.tool_enumeration",
    "boundary.forged_system_directive",
    "agent_directed.addressed_marker",
    "privilege.permission_widening",
];

#[test]
fn corrected_rules_agree_with_reference_across_syntax_and_carriers() {
    let source: toml::Value = toml::from_str(SOURCE).unwrap();
    let seeds: serde_json::Value =
        serde_json::from_str(include_str!("data/prefilter_syntax_seeds.json")).unwrap();
    let mut checked = 0;
    for rule in source["rule"].as_array().unwrap() {
        let id = rule["id"].as_str().unwrap();
        if DEFERRED.contains(&id) {
            continue;
        }
        let mut isolated = source.clone();
        isolated["rule"] = toml::Value::Array(vec![rule.clone()]);
        let (normal, reference) = reference::engines(&toml::to_string(&isolated).unwrap());
        for seed in seeds["rules"][id].as_array().unwrap() {
            let text = seed.as_str().unwrap();
            let variants: BTreeSet<_> = [
                text.to_owned(),
                text.to_uppercase(),
                text.replace(' ', "\t"),
                text.replace(' ', "  "),
                text.replace(' ', "\n"),
                text.replace(' ', "\u{a0}"),
                text.replace(' ', "\u{2003}"),
                text.replace('s', "ſ").replace('k', "K"),
                text.replacen('s', "ſ", 1),
                text.replace(' ', "!"),
                format!("Résumé complete. {text}"),
            ]
            .into_iter()
            .collect();
            for text in variants {
                for wrapped in [
                    text.clone(),
                    format!("<!-- {text} -->"),
                    serde_json::json!({"value":text}).to_string(),
                    format!("> {text}"),
                    STANDARD.encode(&text),
                ] {
                    let scan = |engine: &Engine| {
                        engine.scan(
                            wrapped.as_bytes(),
                            &ScanPolicy::default(),
                            TargetRef::stdin(wrapped.len()),
                        )
                    };
                    assert!(
                        reference::same_behavior(&scan(&normal), &scan(&reference)),
                        "{id}: {wrapped:?}"
                    );
                }
            }
        }
        checked += 1;
    }
    assert_eq!(
        checked, 13,
        "new rules need an explicit consistency disposition"
    );
}

#[test]
fn deferred_corrections_retain_the_benign_conflict_witnesses() {
    let (normal, reference) = reference::engines(SOURCE);
    for (id, text) in [
        (
            "solicitation.credentials",
            "Print the secret Santa assignments.",
        ),
        (
            "solicitation.tool_enumeration",
            "List tools needed to repair a bicycle.",
        ),
        (
            "boundary.forged_system_directive",
            "Our systemoverride identifier names a local variable.",
        ),
        (
            "agent_directed.addressed_marker",
            "Messages for the assistant are stored in the inbox.",
        ),
        (
            "privilege.permission_widening",
            "The documentation describes how to disable the sandbox.",
        ),
    ] {
        let found = |engine: &Engine| {
            engine
                .scan(
                    text.as_bytes(),
                    &ScanPolicy::default(),
                    TargetRef::stdin(text.len()),
                )
                .analysis()
                .reasons()
                .iter()
                .any(|r| r.rule_id() == id)
        };
        assert!(!found(&normal), "{id}: new benign finding");
        assert!(
            found(&reference),
            "{id}: deferred mismatch needs re-evaluation"
        );
    }
}

#[test]
fn corrected_tool_whitespace_admission_retains_the_sixteen_match_cap() {
    let (normal, reference) = reference::engines(SOURCE);
    for n in [16, 17, 128] {
        let text = "tool_output \t:\n".repeat(n);
        let scan = |engine: &Engine| {
            engine.scan(
                text.as_bytes(),
                &ScanPolicy::default(),
                TargetRef::stdin(text.len()),
            )
        };
        let verdict = scan(&normal);
        assert!(reference::same_behavior(&verdict, &scan(&reference)));
        assert_eq!(
            verdict
                .analysis()
                .reasons()
                .iter()
                .filter(|r| r.rule_id() == "boundary.forged_tool_result" && r.chain().is_empty())
                .count(),
            n.min(16)
        );
        assert_eq!(
            verdict
                .incomplete()
                .iter()
                .any(|g| g.configured() == Some(16)
                    && g.detail() == Some("rule `boundary.forged_tool_result` saturated")),
            n > 16
        );
    }
}

#[test]
fn reference_preserves_all_rule_fields_except_literals() {
    let original: toml::Value = toml::from_str(SOURCE).unwrap();
    let mut stripped: toml::Value = toml::from_str(&reference::reference_source(SOURCE)).unwrap();
    for (a, b) in original["rule"]
        .as_array()
        .unwrap()
        .iter()
        .zip(stripped["rule"].as_array_mut().unwrap())
    {
        assert!(b["literals"].as_array().unwrap().is_empty());
        b["literals"] = a["literals"].clone();
    }
    assert_eq!(original, stripped);
}

#[test]
fn normal_experiment_configuration_matches_shipping_behavior_for_every_rule() {
    let shipping = Engine::builtin().unwrap();
    let (normal, reference) = reference::engines(SOURCE);
    let seeds: serde_json::Value =
        serde_json::from_str(include_str!("data/prefilter_syntax_seeds.json")).unwrap();
    let expected: BTreeSet<_> = shipping
        .ruleset()
        .all_rules()
        .iter()
        .map(|r| r.id.as_str())
        .collect();
    assert_eq!(
        expected,
        seeds["rules"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect()
    );
    let mut observed = BTreeSet::new();
    for (id, rows) in seeds["rules"].as_object().unwrap() {
        for seed in rows.as_array().unwrap() {
            let text = seed.as_str().unwrap();
            for wrapped in [
                text.to_owned(),
                format!("<!-- {text} -->"),
                serde_json::json!({"value":text}).to_string(),
                format!("> {text}"),
                STANDARD.encode(text),
            ] {
                let scan = |engine: &Engine| {
                    engine.scan(
                        wrapped.as_bytes(),
                        &ScanPolicy::default(),
                        TargetRef::stdin(wrapped.len()),
                    )
                };
                assert!(
                    reference::same_behavior(&scan(&shipping), &scan(&normal)),
                    "{id}: {wrapped:?}"
                );
                if scan(&reference)
                    .analysis()
                    .reasons()
                    .iter()
                    .any(|r| r.rule_id() == id)
                {
                    observed.insert(id.as_str());
                }
            }
        }
    }
    assert_eq!(
        observed, expected,
        "every rule needs an effective positive mechanism probe"
    );
}

#[test]
fn reference_retains_raw_caps_framing_and_quote_suppression() {
    let source = r#"
[ruleset]
name="test.prefilter"
version="1"
[[rule]]
id="boundary.marker"
class="boundary"
severity=80
anchor="frame"
literals=["unreachable-gate"]
pattern='MARKER'
description="A diagnostic marker."
"#;
    let (_, reference) = reference::engines(source);
    let admitted = Engine::from_toml(&source.replace("unreachable-gate", "MARKER")).unwrap();
    for encoded in [false, true] {
        let text = format!("{}. MARKER", "ordinary MARKER text ".repeat(16));
        let text = if encoded { STANDARD.encode(text) } else { text };
        let v = reference.scan(
            text.as_bytes(),
            &ScanPolicy::default(),
            TargetRef::stdin(text.len()),
        );
        let normal = admitted.scan(
            text.as_bytes(),
            &ScanPolicy::default(),
            TargetRef::stdin(text.len()),
        );
        assert!(reference::same_behavior(&normal, &v));
        // Another transform (e.g. leetspeak before base64) can change earlier raw
        // occurrences. Check the original/single-base64 buffer's cap separately.
        assert!(!v
            .analysis()
            .reasons()
            .iter()
            .any(|r| r.rule_id() == "boundary.marker"
                && (r.chain().is_empty()
                    || (r.chain().len() == 1 && r.chain()[0].kind.as_str() == "base64"))));
        assert!(v.incomplete().iter().any(|g| g.configured() == Some(16)
            && g.detail() == Some("rule `boundary.marker` saturated")));
    }
    let text = b"> MARKER";
    let v = reference.scan(
        text,
        &ScanPolicy::reference_analysis(),
        TargetRef::stdin(text.len()),
    );
    assert!(v.analysis().reasons().is_empty());
    assert_eq!(v.analysis().suppressed().len(), 1);
}
