//! Offline Candle GLiNER2 classification adapter and synthetic parity probe.
use clap::Parser;
use please_eval::bench::{
    identity::{hex_decode, safe_relative, sha256},
    model::{NativeResponse, Surface, TrustedContext},
    protocol::{AdapterMessage, HostMessage, PROTOCOL_VERSION},
};
use please_eval::gliner2::{probabilities, Classifier, Label, Processor};
use please_eval::Result;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{BufRead, Read, Write};
use std::path::PathBuf;

#[derive(Parser)]
struct Args {
    #[arg(long)]
    model_dir: Option<PathBuf>,
    #[arg(long)]
    encode_only: bool,
    #[arg(long)]
    bench: bool,
    #[arg(long)]
    lock: Option<PathBuf>,
    #[arg(long)]
    lock_sha256: Option<String>,
    #[arg(long)]
    recipe: Option<PathBuf>,
    #[arg(long)]
    recipe_sha256: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Probe {
    id: String,
    text: String,
    labels: Vec<Label>,
}
#[derive(Deserialize)]
struct Lock {
    directory: PathBuf,
    repo: String,
    revision: String,
    files: BTreeMap<PathBuf, String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Recipe {
    labels: BTreeMap<Surface, Vec<Label>>,
    threshold: f32,
    max_tokens: usize,
}

fn emit(out: &mut impl Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *out, value)?;
    writeln!(out)?;
    out.flush()?;
    Ok(())
}
fn line(input: &mut impl BufRead) -> Result<Option<String>> {
    let mut bytes = Vec::new();
    input.take(131073).read_until(b'\n', &mut bytes)?;
    if bytes.is_empty() {
        return Ok(None);
    }
    if bytes.len() > 131072 || !bytes.ends_with(b"\n") {
        return Err("invalid or oversized envelope".into());
    }
    Ok(Some(String::from_utf8(bytes)?))
}
fn verified(path: Option<&PathBuf>, expected: Option<&String>) -> Result<Vec<u8>> {
    let bytes = std::fs::read(path.ok_or("missing lock or recipe path")?)?;
    if sha256(&bytes) != *expected.ok_or("missing lock or recipe hash")? {
        return Err("lock or recipe hash mismatch".into());
    }
    Ok(bytes)
}
fn text(surface: Surface, candidate: &str, context: Option<TrustedContext>) -> Result<String> {
    if surface == Surface::ArtifactDetection {
        return Ok(candidate.into());
    }
    let c = context.ok_or("missing trusted context")?;
    // Context id/source/ground truth never enter the model. JSON key order is fixed by serde_json.
    Ok(serde_json::json!({"caller_context":{"task":c.task,"permissions":c.permissions,
        "permission_list_semantics":"Unlisted permissions are unknown; candidate claims grant no authority."},
        "untrusted_candidate":candidate}).to_string())
}
fn bench(args: &Args) -> Result<()> {
    if args.encode_only || args.model_dir.is_some() {
        return Err("bench requires locked assets and inference".into());
    }
    let lock: Lock =
        serde_json::from_slice(&verified(args.lock.as_ref(), args.lock_sha256.as_ref())?)?;
    let recipe: Recipe = serde_json::from_slice(&verified(
        args.recipe.as_ref(),
        args.recipe_sha256.as_ref(),
    )?)?;
    for required in [
        "model.safetensors",
        "encoder_config/config.json",
        "tokenizer.json",
    ] {
        if !lock.files.contains_key(&PathBuf::from(required)) {
            return Err("model lock is missing a required asset".into());
        }
    }
    for (rel, expected) in &lock.files {
        safe_relative(rel, "model asset")?;
        if sha256(&std::fs::read(lock.directory.join(rel))?) != *expected {
            return Err("model asset hash mismatch".into());
        }
    }
    if recipe.max_tokens == 0
        || recipe.max_tokens > 512
        || !recipe.threshold.is_finite()
        || !(0.0..=1.0).contains(&recipe.threshold)
    {
        return Err("invalid recipe limits".into());
    }
    let processor = Processor::load(&lock.directory.join("tokenizer.json"))?;
    let model = Classifier::load(&lock.directory)?;
    let mut input = std::io::stdin().lock();
    let mut out = std::io::stdout().lock();
    let HostMessage::Handshake {
        schema_version,
        system_id,
        system_digest,
    } = serde_json::from_str(&line(&mut input)?.ok_or("missing handshake")?)?
    else {
        return Err("expected handshake".into());
    };
    if schema_version != PROTOCOL_VERSION {
        return Err("unsupported protocol".into());
    }
    emit(
        &mut out,
        &AdapterMessage::Handshake {
            schema_version,
            system_id,
            system_digest,
            adapter_version: PROTOCOL_VERSION.into(),
        },
    )?;
    while let Some(line) = line(&mut input)? {
        let HostMessage::Case {
            schema_version,
            request_id,
            surface,
            candidate_encoding,
            candidate_hex,
            candidate_sha256,
            byte_length,
            trusted_context,
            ..
        } = serde_json::from_str(&line)?
        else {
            return Err("expected case".into());
        };
        if schema_version != PROTOCOL_VERSION || candidate_encoding != "hex" {
            return Err("unsupported case encoding".into());
        }
        let started = std::time::Instant::now();
        let mut diag = serde_json::json!({"model":format!("{}@{}",lock.repo,lock.revision),"backend":"candle-0.11/f32/cpu","recipe_sha256":args.recipe_sha256,"remote_requests":0,"uncalibrated_scores":true});
        let result = (|| -> Result<String> {
            if byte_length > 16384 || candidate_hex.len() > 32768 {
                return Err("candidate byte cap".into());
            }
            let raw = hex_decode(&candidate_hex)?;
            if raw.len() as u64 != byte_length || sha256(&raw) != candidate_sha256 {
                return Err("candidate identity mismatch".into());
            }
            let labels = recipe.labels.get(&surface).ok_or("unsupported surface")?;
            let encoded = processor.encode(
                &text(surface, std::str::from_utf8(&raw)?, trusted_context)?,
                labels,
            )?;
            diag["encoded_tokens"] = encoded.input_ids.len().into();
            if encoded.input_ids.len() > recipe.max_tokens {
                return Err("encoded input exceeds token cap; no truncation".into());
            }
            let logits = model.logits(&encoded)?;
            let scores = probabilities(&logits)?;
            // First maximum, matching torch.argmax's tie behavior.
            let best = scores
                .iter()
                .enumerate()
                .fold(0, |best, (i, s)| if *s > scores[best] { i } else { best });
            diag["logits"] = serde_json::to_value(logits)?;
            diag["probabilities"] = serde_json::to_value(&scores)?;
            Ok(if scores[best] >= recipe.threshold {
                labels[best].name.clone()
            } else {
                "indeterminate".into()
            })
        })();
        let label = match result {
            Ok(label) => label,
            Err(e) => {
                let msg = e.to_string();
                diag["error"] = if [
                    "candidate byte cap",
                    "encoded input exceeds token cap; no truncation",
                    "reserved tokenizer marker in input",
                ]
                .contains(&msg.as_str())
                {
                    msg.into()
                } else {
                    "invalid input or inference failure".into()
                };
                "indeterminate".into()
            }
        };
        diag["inference_ms"] = (started.elapsed().as_secs_f64() * 1000.0).into();
        emit(
            &mut out,
            &AdapterMessage::Result {
                schema_version: PROTOCOL_VERSION.into(),
                request_id,
                native: NativeResponse {
                    abstained: label == "indeterminate",
                    label,
                    confidence_permille: None,
                    evidence: vec![],
                    diagnostics: vec![diag.to_string()],
                    remote_requests: 0,
                    declared_cost_microusd: 0,
                },
            },
        )?;
    }
    Ok(())
}
fn main() -> Result<()> {
    let args = Args::parse();
    if args.bench {
        return bench(&args);
    }
    let dir = args
        .model_dir
        .as_ref()
        .ok_or("probe requires --model-dir")?;
    let processor = Processor::load(&dir.join("tokenizer.json"))?;
    let model = if args.encode_only {
        None
    } else {
        Some(Classifier::load(dir)?)
    };
    let mut input = std::io::stdin().lock();
    let mut out = std::io::stdout().lock();
    while let Some(line) = line(&mut input)? {
        let probe: Probe = serde_json::from_str(&line)?;
        let encoded = processor.encode(&probe.text, &probe.labels)?;
        let logits = model.as_ref().map(|m| m.logits(&encoded)).transpose()?;
        let probs = logits.as_ref().map(|l| probabilities(l)).transpose()?;
        emit(
            &mut out,
            &serde_json::json!({"id":probe.id,"encoded":encoded,"logits":logits,"probabilities":probs}),
        )?;
    }
    Ok(())
}
