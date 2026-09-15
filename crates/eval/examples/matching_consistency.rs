//! Offline-only matching experiment; not part of the production CLI or core feature set.
//! run PACKAGE SHA256 RULES normal|reference|shipping LABEL
//! inspect PACKAGE SHA256 RULES normal|reference ROW_SELECTION.json
//! pair PACKAGE SHA256 RULES reference|shipping|OTHER_RULES OUTPUT.json
#[path = "../../core/tests/support/prefilter_reference.rs"]
#[allow(dead_code)]
// This shared test module also exposes helpers used only by core integration tests.
mod reference;

use please_core::{Engine, RiskLevel, ScanProfile, TargetRef};
use please_eval::{
    product::{Mode, Runtime},
    rows::Row,
    run::EvaluationRun,
    slice::SliceSet,
    Result,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, fs, io::Write, path::Path};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Frozen {
    corpus: SliceSet,
    rows: BTreeMap<String, Vec<Row>>,
}

fn write_new(path: &Path, data: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(data)?;
    file.sync_all()?;
    Ok(())
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 7 {
        return Err(
            "run|inspect PACKAGE SHA256 RULES normal|reference|shipping LABEL|SELECTION".into(),
        );
    }
    let bytes = fs::read(&args[2])?;
    if format!("{:x}", Sha256::digest(&bytes)) != args[3] {
        return Err("frozen input checksum mismatch".into());
    }
    let frozen: Frozen = serde_json::from_slice(&bytes)?;
    let source = fs::read_to_string(&args[4])?;
    if args[1] == "pair" {
        let left = Engine::from_toml(&source)?;
        let right_source = match args[5].as_str() {
            "reference" => reference::reference_source(&source),
            "shipping" => include_str!("../../../rules/builtin.toml").to_owned(),
            _ => fs::read_to_string(&args[5])?,
        };
        let right = if args[5] == "shipping" {
            Engine::builtin()?
        } else {
            Engine::from_toml(&right_source)?
        };
        let runtime =
            Runtime::structural(Mode::Product, ScanProfile::Enforcement, RiskLevel::High)?;
        let (a, b) = (runtime.session(&left), runtime.session(&right));
        let mut slices = BTreeMap::new();
        for (sid, rows) in &frozen.rows {
            let (mut different, mut suppressed, mut gaps) = (Vec::new(), Vec::new(), Vec::new());
            for row in rows {
                let a = a.scan(
                    row.text.as_bytes(),
                    TargetRef::buffer(&row.id, row.text.len()),
                );
                let b = b.scan(
                    row.text.as_bytes(),
                    TargetRef::buffer(&row.id, row.text.len()),
                );
                if !reference::same_behavior(&a, &b) {
                    different.push(&row.id);
                }
                if a.analysis().suppressed() != b.analysis().suppressed() {
                    suppressed.push(&row.id);
                }
                if a.incomplete() != b.incomplete() {
                    let detail = |v: &please_core::Verdict| {
                        v.incomplete().iter().map(|g| serde_json::json!({
                        "cause":g.cause().as_str(),"configured":g.configured(),"detail":g.detail()
                    })).collect::<Vec<_>>()
                    };
                    gaps.push(
                        serde_json::json!({"id":row.id,"before":detail(&a),"after":detail(&b)}),
                    );
                }
            }
            slices.insert(
                sid,
                serde_json::json!({"rows":rows.len(),"full_different_ids":different,
                "suppression_different_ids":suppressed,"gap_differences":gaps}),
            );
        }
        return write_new(
            Path::new(&args[6]),
            &serde_json::to_vec_pretty(&serde_json::json!({
                "input_sha256":args[3],"left_source_sha256":format!("{:x}",Sha256::digest(source.as_bytes())),
                "right_source_sha256":format!("{:x}",Sha256::digest(right_source.as_bytes())),"slices":slices
            }))?,
        );
    }
    let build = std::time::Instant::now();
    let engine = match args[5].as_str() {
        "normal" => Engine::from_toml(&source)?,
        "reference" => Engine::from_toml(&reference::reference_source(&source))?,
        "shipping" => {
            if source != include_str!("../../../rules/builtin.toml") {
                return Err("shipping mode source differs from compiled rules".into());
            }
            Engine::builtin()?
        }
        _ => return Err("unknown configuration".into()),
    };
    let preparation_ns = build.elapsed().as_nanos();
    let runtime = Runtime::structural(Mode::Product, ScanProfile::Enforcement, RiskLevel::High)?;
    if args[1] == "inspect" {
        let selected: BTreeMap<String, Vec<String>> = serde_json::from_slice(&fs::read(&args[6])?)?;
        let session = runtime.session(&engine);
        for (slice, ids) in selected {
            let rows = frozen.rows.get(&slice).ok_or("unknown slice")?;
            for id in ids {
                let row = rows.iter().find(|r| r.id == id).ok_or("unknown row")?;
                let verdict = session.scan(
                    row.text.as_bytes(),
                    TargetRef::buffer(&row.id, row.text.len()),
                );
                // No prompt/excerpt redistribution in diagnostic output.
                println!(
                    "{}",
                    serde_json::json!({"slice":slice,"id":id,"score":verdict.score(),
                    "gaps":verdict.incomplete().iter().map(|g| serde_json::json!({"cause":g.cause().as_str(),"configured":g.configured(),"detail":g.detail()})).collect::<Vec<_>>() })
                );
            }
        }
        return Ok(());
    }
    if args[1] != "run" {
        return Err("expected run or inspect".into());
    }
    let root = please_eval::cache::root()?.join("results");
    let directory = root.join(&args[6]);
    let ids: Vec<_> = frozen.corpus.slices.iter().map(|s| s.id.clone()).collect();
    let mut run = EvaluationRun::create(
        &root,
        &args[6],
        &runtime,
        &engine,
        &format!("matching-consistency/{}", args[5]),
        frozen.corpus,
    )?;
    let mut timings = BTreeMap::new();
    for id in ids {
        let start = std::time::Instant::now();
        let result = run.scan_slice(&id, frozen.rows.get(&id).ok_or("missing frozen rows")?)?;
        timings.insert(id.clone(), start.elapsed().as_nanos());
        println!("{id}: {}/{}", result.hits, result.rows);
    }
    run.finish()?;
    write_new(&directory.join("input-sha256.txt"), args[3].as_bytes())?;
    write_new(
        &directory.join("experiment.json"),
        &serde_json::to_vec_pretty(&serde_json::json!({
            "configuration":args[5],"source_sha256":format!("{:x}",Sha256::digest(source.as_bytes())),
            "preparation_ns":preparation_ns,"slice_ns":timings,
            "reference_is_test_only":true,"normal_and_reference_prepare_supplied_rules":true
        }))?,
    )?;
    let report = please_eval::run::report(&root, &args[6], false)?;
    please_eval::corpus_presentation::save_bundle(&report, &directory)?;
    Ok(())
}
