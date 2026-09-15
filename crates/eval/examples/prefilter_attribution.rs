//! Offline, test-only timing of separately frozen literal corrections.
//! PACKAGE SHA256 CONFIGS.json OUTPUT.json
use please_core::{Engine, ScanPolicy, TargetRef};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, hint::black_box, io::Write, time::Instant};

#[derive(Deserialize)]
struct Input {
    id: String,
    text: String,
}
#[derive(Deserialize)]
struct Package {
    rows: BTreeMap<String, Vec<Input>>,
}
#[derive(Deserialize)]
struct Configuration {
    label: String,
    source: String,
}

fn main() -> please_eval::Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 5 {
        return Err("PACKAGE SHA256 CONFIGS.json OUTPUT.json".into());
    }
    let bytes = fs::read(&args[1])?;
    if format!("{:x}", Sha256::digest(&bytes)) != args[2] {
        return Err("input hash mismatch".into());
    }
    let package: Package = serde_json::from_slice(&bytes)?;
    let configs: Vec<Configuration> = serde_json::from_slice(&fs::read(&args[3])?)?;
    let policy = ScanPolicy::default();
    let mut construction = Vec::new();
    let mut hashes = Vec::new();
    let engines = configs
        .iter()
        .map(|c| {
            let source = fs::read_to_string(&c.source).unwrap();
            hashes.push(format!("{:x}", Sha256::digest(source.as_bytes())));
            let start = Instant::now();
            let engine = Engine::from_toml(&source).unwrap();
            construction.push(start.elapsed().as_nanos());
            engine
        })
        .collect::<Vec<_>>();
    let scan = |i: usize, rows: &[Input]| {
        for row in rows {
            black_box(engines[i].scan(
                black_box(row.text.as_bytes()),
                &policy,
                TargetRef::buffer(&row.id, row.text.len()),
            ));
        }
    };
    for i in 0..configs.len() {
        for rows in package.rows.values() {
            scan(i, rows);
        }
    }
    let mut measurements: Vec<BTreeMap<String, Vec<u128>>> = vec![BTreeMap::new(); configs.len()];
    // Rotation plus alternating direction reduces fixed-order cache/drift bias.
    for trial in 0..5 {
        for offset in 0..configs.len() {
            let offset = if trial % 2 == 0 {
                offset
            } else {
                configs.len() - 1 - offset
            };
            let i = (offset + trial * 7) % configs.len();
            for (name, rows) in &package.rows {
                let start = Instant::now();
                scan(i, rows);
                measurements[i]
                    .entry(name.clone())
                    .or_default()
                    .push(start.elapsed().as_nanos());
            }
        }
        eprintln!("attribution trial {} complete", trial + 1);
    }
    let results=configs.iter().enumerate().map(|(i,c)| (c.label.clone(),json!({
        "source_sha256":hashes[i],"construction_ns":construction[i],"samples_ns":measurements[i]
    }))).collect::<BTreeMap<_,_>>();
    let output = json!({"input_sha256":args[2],"configurations":results,"policy":policy,
        "method":"Five rotating-order warmed trials; source preparation separate; no saved-row publication in timed regions.",
        "rows":package.rows.iter().map(|(k,v)|(k,v.len())).collect::<BTreeMap<_,_>>()});
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&args[4])?;
    f.write_all(&serde_json::to_vec_pretty(&output)?)?;
    Ok(())
}
