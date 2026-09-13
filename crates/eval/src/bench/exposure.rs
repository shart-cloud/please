use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

use crate::bench::identity::nonempty;
use crate::bench::model::{BenchResult, ExposureRecord};
use crate::bench::runner::verify_saved_run;
use crate::Result;

pub fn record(
    run_directory: &Path,
    out: &Path,
    use_kind: &str,
    recorded_at: &str,
) -> Result<usize> {
    nonempty(use_kind, "exposure use_kind")?;
    nonempty(recorded_at, "exposure recorded_at")?;
    if out.exists() {
        return Err(format!(
            "{} already exists; exposure records never overwrite",
            out.display()
        )
        .into());
    }
    let run = verify_saved_run(run_directory)?;
    let input = File::open(run_directory.join("results.jsonl"))?;
    let mut cases: BTreeMap<String, ExposureRecord> = BTreeMap::new();
    for line in BufReader::new(input).split(b'\n') {
        let line = line?;
        if line.is_empty() {
            continue;
        }
        let row: BenchResult = serde_json::from_slice(&line)?;
        let record = ExposureRecord {
            schema_version: "please-bench-exposure/v1".into(),
            pack_digest: run.pack_digest.clone(),
            case_id: row.case_id.clone(),
            input_sha256: row.input_sha256,
            normalized_sha256: row.normalized_input_sha256,
            family_id: row.family_id,
            use_kind: use_kind.into(),
            recorded_at: recorded_at.into(),
        };
        if let Some(previous) = cases.insert(record.case_id.clone(), record.clone()) {
            if previous.input_sha256 != record.input_sha256
                || previous.normalized_sha256 != record.normalized_sha256
                || previous.family_id != record.family_id
            {
                return Err("one case id produced conflicting exposure identities".into());
            }
        }
    }
    let file = OpenOptions::new().write(true).create_new(true).open(out)?;
    let mut writer = BufWriter::new(file);
    for record in cases.values() {
        serde_json::to_writer(&mut writer, record)?;
        writer.write_all(b"\n")?;
    }
    writer.flush()?;
    writer.get_ref().sync_all()?;
    Ok(cases.len())
}
