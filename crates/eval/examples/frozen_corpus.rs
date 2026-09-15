//! Reproduce detector experiments against immutable input bytes, including repository prose.
//! All acquisition, integrity, scanning, and reporting use the ordinary evaluator APIs.
use std::{collections::BTreeMap, env, fs, path::Path};

use please_core::{Engine, ScanProfile};
use please_eval::{
    cases, fetch,
    manifest::Manifest,
    product::{Mode, Runtime},
    rows::Row,
    run::EvaluationRun,
    slice::{Origin, SliceSet},
    Result,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Frozen {
    corpus: SliceSet,
    rows: BTreeMap<String, Vec<Row>>,
}

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("freeze") if args.len() == 3 => {
            let corpus = SliceSet::load()?;
            let mut rows = BTreeMap::new();
            for slice in &corpus.slices {
                let data = match slice.origin {
                    Origin::Query { .. } => {
                        let data = fetch::read_cache(&slice.id)?;
                        Manifest::read(&slice.id)?.verify(&slice.id, &data)?;
                        data
                    }
                    Origin::Local { reader } => cases::read(reader)?,
                };
                rows.insert(slice.id.clone(), data);
            }
            let bytes = serde_json::to_vec(&Frozen { corpus, rows })?;
            use std::io::Write;
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&args[2])?
                .write_all(&bytes)?;
            println!("{:x}", Sha256::digest(&bytes));
        }
        Some("run") if args.len() >= 7 => {
            // run PACKAGE SHA256 LABEL THRESHOLD SLICE...; no implicit data selection.
            let bytes = fs::read(&args[2])?;
            if format!("{:x}", Sha256::digest(&bytes)) != args[3] {
                return Err("frozen input checksum mismatch".into());
            }
            let mut frozen: Frozen = serde_json::from_slice(&bytes)?;
            for id in &args[6..] {
                if !frozen.corpus.slices.iter().any(|s| &s.id == id)
                    || !frozen.rows.contains_key(id)
                {
                    return Err(format!("unknown frozen slice: {id}").into());
                }
            }
            frozen.corpus.slices.retain(|s| args[6..].contains(&s.id));
            let runtime = Runtime::structural(
                Mode::Product,
                ScanProfile::Enforcement,
                please_eval::metrics::parse_floor(&args[5])?,
            )?;
            let engine = Engine::builtin()?;
            let root = please_eval::cache::root()?.join("results");
            let ids: Vec<_> = frozen.corpus.slices.iter().map(|s| s.id.clone()).collect();
            let mut run = EvaluationRun::create(
                &root,
                &args[4],
                &runtime,
                &engine,
                "builtin",
                frozen.corpus,
            )?;
            for id in ids {
                let start = std::time::Instant::now();
                let summary = run.scan_slice(&id, &frozen.rows[&id])?;
                println!(
                    "{id}: {}/{}; {:.3}s",
                    summary.hits,
                    summary.rows,
                    start.elapsed().as_secs_f64()
                );
            }
            run.finish()?;
            let report = please_eval::run::report(&root, &args[4], false)?;
            please_eval::corpus_presentation::save_bundle(&report, &root.join(&args[4]))?;
            // Record the separately verified input identity beside the ordinary saved run.
            fs::write(root.join(&args[4]).join("input-sha256.txt"), &args[3])?;
        }
        _ => {
            return Err(format!(
                "usage: {} freeze PACKAGE | run PACKAGE SHA256 LABEL THRESHOLD SLICE...",
                Path::new(&args[0]).display()
            )
            .into())
        }
    }
    Ok(())
}
