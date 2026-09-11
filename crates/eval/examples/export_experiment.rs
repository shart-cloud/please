//! Native-only experiment runner. No inference/network; one reusable engine, complete verdicts.
use please_core::{Engine, ExportPolicy, Outcome, ScanPolicy, ScanSource, TargetRef};
use serde_json::{json, Value};
use std::{path::Path, time::Instant};
fn decision(v: &please_core::Verdict, p: &ScanPolicy) -> &'static str {
    if v.outcome() == Outcome::RiskFound && v.is_at_or_above(p.threshold) {
        "block"
    } else if v.is_incomplete() || v.outcome() != Outcome::Clean {
        "review"
    } else {
        "allow"
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("usage: export_experiment REPO CASES_JSONL NEW_OUTPUT".into());
    }
    let root = Path::new(&args[1]);
    let restricted = ExportPolicy::from_toml(&std::fs::read_to_string(
        root.join("examples/export-policy.toml"),
    )?)?;
    let approved = ExportPolicy::from_toml(&std::fs::read_to_string(
        root.join("tests/fixtures/action-evidence/approved.toml"),
    )?)?;
    let start = Instant::now();
    let engine = Engine::builtin()?;
    let init_us = start.elapsed().as_micros();
    let mut rows = Vec::new();
    for line in std::fs::read_to_string(&args[2])?
        .lines()
        .filter(|s| !s.trim().is_empty())
    {
        let row: Value = serde_json::from_str(line)?;
        let text = row["text"].as_str().ok_or("text missing")?;
        let source = match row["source"].as_str() {
            Some("security_reference") => ScanSource::SecurityReference,
            Some("untrusted_tool_response") => ScanSource::UntrustedToolResponse,
            Some("untrusted_user_input") => ScanSource::UntrustedUserInput,
            _ => return Err("unknown source".into()),
        };
        let base = ScanPolicy::for_source(source);
        let mut policy = base.clone();
        policy.export_policy = Some(match row["policy"].as_str() {
            Some("restricted") => restricted.clone(),
            Some("approved") => approved.clone(),
            _ => return Err("unknown policy".into()),
        });
        let scan = |p: &ScanPolicy| {
            engine.scan(
                text.as_bytes(),
                p,
                TargetRef::buffer(row["id"].as_str().unwrap_or("case"), text.len()),
            )
        };
        let old = scan(&base);
        let start = Instant::now();
        let new = scan(&policy);
        let first_us = start.elapsed().as_micros();
        let mut times = Vec::new();
        for _ in 0..5 {
            let start = Instant::now();
            std::hint::black_box(scan(&policy));
            times.push(start.elapsed().as_micros());
        }
        times.sort();
        rows.push(json!({"case":row,"baseline_decision":decision(&old,&base),"export_decision":decision(&new,&policy),"baseline":old,"export":new,"first_us":first_us,"warm_median_us":times[2],"engine_init_us":init_us}));
    }
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[3])?;
    use std::io::Write;
    for row in rows {
        writeln!(output, "{}", serde_json::to_string(&row)?)?;
    }
    Ok(())
}
