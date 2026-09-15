//! Compare literal-gate costs using the real lazy matcher, outside production.
//! cargo run --release -p please-core --example role_marker_cost -- OLD.toml NEW.toml
//! Parsing/construction is excluded; cold measurements include first-use regex compilation.
use std::{hint::black_box, time::Instant};

use please_core::{
    finalize::evidence::Evidence,
    matcher::Matcher,
    ruleset::{Ruleset, RulesetLimits},
};

fn matcher(rules: &Ruleset) -> Matcher {
    Matcher::build(
        rules.clone(),
        vec![None; rules.len()],
        RulesetLimits::default(),
    )
}

fn scan(matcher: &Matcher, text: &[u8]) -> u128 {
    let mut evidence = Evidence::new();
    let start = Instant::now();
    black_box(matcher.find(text, 16, &mut evidence));
    let elapsed = start.elapsed().as_nanos();
    black_box(evidence);
    elapsed
}

fn median(mut values: Vec<u128>) -> u128 {
    values.sort_unstable();
    values[values.len() / 2]
}

fn main() {
    let paths: Vec<_> = std::env::args().skip(1).collect();
    assert_eq!(
        paths.len(),
        2,
        "expected baseline and candidate rules paths"
    );
    let rules: Vec<_> = paths
        .iter()
        .map(|path| Ruleset::from_toml(&std::fs::read_to_string(path).unwrap()).unwrap())
        .collect();
    for (name, unit) in [
        (
            "ordinary_prose",
            "The quarterly report covers revenue and staffing. ",
        ),
        (
            "ordinary_role_mentions",
            "The system is ready and the assistant maintains the calendar. ",
        ),
        ("off_frame_markers", "ordinary [ assistant ] text "),
    ] {
        for size in [4096, 65536, 1048576] {
            let text = unit.repeat(size / unit.len() + 1).into_bytes();
            let text = &text[..size];
            let mut cold = [Vec::new(), Vec::new()];
            let mut warm = [Vec::new(), Vec::new()];
            for trial in 0..15 {
                // Alternate order to reduce drift bias; both matchers start with empty slots.
                for index in if trial % 2 == 0 { [0, 1] } else { [1, 0] } {
                    let matcher = matcher(&rules[index]);
                    cold[index].push(scan(&matcher, text));
                    for _ in 0..9 {
                        warm[index].push(scan(&matcher, text));
                    }
                }
            }
            println!(
                "{}",
                serde_json::json!({
                    "input": name, "bytes": size, "cold_samples": 15, "warm_samples": 135,
                    "baseline_cold_median_ns": median(cold[0].clone()),
                    "candidate_cold_median_ns": median(cold[1].clone()),
                    "baseline_warm_median_ns": median(warm[0].clone()),
                    "candidate_warm_median_ns": median(warm[1].clone()),
                })
            );
        }
    }
}
