//! Test-only warmed matching benchmark. No production bypass or changed scan limits.
//! prefilter_runtime BASELINE.toml ACCEPTED.toml OUTPUT.json
#[path = "../../core/tests/support/prefilter_reference.rs"]
#[allow(dead_code)]
mod reference;
use please_core::{Engine, ScanPolicy, TargetRef};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{fs, hint::black_box, io::Write, time::Instant};

fn main() -> please_eval::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 4 {
        return Err("BASELINE.toml ACCEPTED.toml OUTPUT.json".into());
    }
    let baseline = fs::read_to_string(&args[1])?;
    let accepted = fs::read_to_string(&args[2])?;
    let sources = [
        baseline.clone(),
        accepted.clone(),
        reference::reference_source(&baseline),
    ];
    let names = ["baseline", "accepted", "reference"];
    let policy = ScanPolicy::default();
    let mut preparation = Vec::new();
    let engines = sources
        .iter()
        .map(|s| {
            let start = Instant::now();
            let e = Engine::from_toml(s).unwrap();
            preparation.push(start.elapsed().as_nanos());
            e
        })
        .collect::<Vec<_>>();
    let mut cases = Vec::new();
    for size in [1024, 16384, 131072] {
        for (name, unit) in [
            ("ordinary_prose", "The spring garden contains red flowers and a stone path. Birds rest beside the pond. "),
            ("many_literals", "ignore revised system forget assistant tool_output reveal share grant transfer curl "),
        ] {
            cases.push((format!("{name}_{size}"), unit.repeat(size / unit.len() + 1)[..size].to_owned(), 20));
        }
    }
    for n in [16, 17, 128, 4096] {
        cases.push((
            format!("tool_whitespace_{n}"),
            "tool_output \t:\n".repeat(n),
            20,
        ));
        cases.push((
            format!("off_frame_unicode_roles_{n}"),
            format!("{}. [ſyſtem]", "ordinary [ſyſtem] text ".repeat(n)),
            20,
        ));
    }
    cases.push((
        "input_over_limit".to_owned(),
        "x".repeat(1024 * 1024 + 1),
        20,
    ));
    let mut output = Vec::new();
    for (name, text, iterations) in cases {
        let scan = |i: usize| {
            engines[i].scan(
                black_box(text.as_bytes()),
                &policy,
                TargetRef::stdin(text.len()),
            )
        };
        // Warm all engines before timing; supplied source preparation is reported separately.
        let verdicts = (0..3).map(scan).collect::<Vec<_>>();
        let mut samples = [Vec::new(), Vec::new(), Vec::new()];
        for round in 0..5 {
            for offset in 0..3 {
                let i = (round + offset) % 3;
                let start = Instant::now();
                for _ in 0..iterations {
                    black_box(scan(i));
                }
                samples[i].push(start.elapsed().as_nanos() / iterations);
            }
        }
        let configs = (0..3).map(|i| {
            let v = &verdicts[i];
            let mut sorted = samples[i].clone(); sorted.sort();
            (names[i], json!({"samples_ns_per_scan":samples[i],"median_ns_per_scan":sorted[2],
                "score":v.score(),"outcome":v.outcome(),"findings":v.analysis().reasons().len(),
                "suppressed":v.analysis().suppressed().len(),"gaps":v.incomplete().iter().map(|g| json!({
                    "cause":g.cause().as_str(),"configured":g.configured(),"detail":g.detail()
                })).collect::<Vec<_>>() }))
        }).collect::<std::collections::BTreeMap<_,_>>();
        output.push(json!({"case":name,"bytes":text.len(),"iterations_per_sample":iterations,"configs":configs,
            "accepted_equals_reference":reference::same_behavior(&verdicts[1],&verdicts[2])}));
    }
    let result = json!({"policy":policy,"method":"Warmed supplied engines; five rotating-order samples per case; construction separate; single process.",
        "source_sha256":sources.iter().map(|s| format!("{:x}",Sha256::digest(s.as_bytes()))).collect::<Vec<_>>(),
        "preparation_ns":preparation,"cases":output});
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[3])?;
    file.write_all(&serde_json::to_vec_pretty(&result)?)?;
    Ok(())
}
