//! Deterministic JSONL adapter used to prove the bench protocol and failure semantics.
//! It is an instrument fixture, not an accuracy claim or production detector.

use std::io::{BufRead, BufReader, BufWriter, Write};
use std::time::Duration;

use please_eval::bench::identity::{hex_decode, sha256};
use please_eval::bench::model::NativeResponse;
use please_eval::bench::protocol::{AdapterMessage, HostMessage, PROTOCOL_VERSION};

fn main() {
    if let Err(error) = run() {
        eprintln!("fixture adapter: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mode = std::env::args().nth(1).unwrap_or_else(|| "detect".into());
    if let Some(path) = std::env::var_os("PLEASE_BENCH_PID_FILE") {
        std::fs::write(path, std::process::id().to_string())?;
    }
    let stdin = std::io::stdin();
    let mut lines = BufReader::new(stdin.lock()).lines();
    let handshake: HostMessage = serde_json::from_str(&lines.next().ok_or("missing handshake")??)?;
    let (system_id, system_digest) = match handshake {
        HostMessage::Handshake {
            schema_version,
            system_id,
            system_digest,
        } if schema_version == PROTOCOL_VERSION => (system_id, system_digest),
        _ => return Err("invalid handshake".into()),
    };
    let stdout = std::io::stdout();
    let mut output = BufWriter::new(stdout.lock());
    if mode == "bad-handshake" {
        writeln!(output, "{{garbage")?;
        output.flush()?;
        std::thread::sleep(Duration::from_secs(60));
        return Ok(());
    }
    send(
        &mut output,
        &AdapterMessage::Handshake {
            schema_version: PROTOCOL_VERSION.into(),
            system_id,
            system_digest,
            adapter_version: PROTOCOL_VERSION.into(),
        },
    )?;
    if mode == "hang-before-read" {
        std::thread::sleep(Duration::from_secs(60));
        return Ok(());
    }
    for line in lines {
        let request: HostMessage = serde_json::from_str(&line?)?;
        let HostMessage::Case {
            schema_version,
            request_id,
            surface,
            candidate_encoding,
            candidate_hex,
            candidate_sha256,
            byte_length,
            provenance: _,
            trusted_context,
        } = request
        else {
            return Err("unexpected second handshake".into());
        };
        if schema_version != PROTOCOL_VERSION || candidate_encoding != "hex" {
            return Err("invalid case envelope".into());
        }
        let candidate = hex_decode(&candidate_hex)?;
        if candidate.len() as u64 != byte_length || sha256(&candidate) != candidate_sha256 {
            return Err("candidate identity mismatch".into());
        }
        if mode == "swap-source-crash-once" {
            let source = std::env::var_os("PLEASE_BENCH_SWAP_SOURCE").ok_or("missing source")?;
            let marker = std::env::var_os("PLEASE_BENCH_SWAP_MARKER").ok_or("missing marker")?;
            if !std::path::Path::new(&marker).exists() {
                std::fs::write(source, b"source replaced after staging")?;
                std::fs::write(marker, b"done")?;
                std::process::exit(17);
            }
        }
        if mode == "corrupt-staged-crash" {
            let staged = std::path::PathBuf::from(
                std::env::var_os("PLEASE_BENCH_CORRUPT_STAGED").ok_or("missing staged path")?,
            );
            let replacement = staged.with_extension("replacement");
            std::fs::write(&replacement, b"corrupt staged executable")?;
            std::fs::rename(replacement, staged)?;
            std::process::exit(17);
        }
        match mode.as_str() {
            "hang" => {
                std::thread::sleep(Duration::from_secs(60));
                continue;
            }
            "crash" => std::process::exit(17),
            "malformed" => {
                writeln!(output, "{{broken json")?;
                output.flush()?;
                continue;
            }
            "missing" => return Ok(()),
            "oversized" => {
                output.write_all(&vec![b'x'; 2 * 1024 * 1024])?;
                output.flush()?;
                continue;
            }
            "spam-newlines" => loop {
                output.write_all(b"\n")?;
                output.flush()?;
            },
            "noisy" | "stderr-burst" => {
                std::io::stderr().write_all(&vec![b'e'; 64 * 1024])?;
                std::io::stderr().flush()?;
            }
            _ => {}
        }
        let label = match surface {
            please_eval::bench::model::Surface::ArtifactDetection => {
                let text = String::from_utf8_lossy(&candidate).to_lowercase();
                if text.contains("ignore") || text.contains("secret") {
                    "injection"
                } else {
                    "benign"
                }
            }
            please_eval::bench::model::Surface::ContextualAlignment => {
                let task = trusted_context
                    .as_ref()
                    .map(|context| context.task.to_lowercase())
                    .unwrap_or_default();
                if task.contains("authorized") {
                    "aligned_instruction"
                } else if task.contains("analyze") || task.contains("quote") {
                    "non_instruction"
                } else if task.is_empty() {
                    "indeterminate"
                } else {
                    "conflicting_instruction"
                }
            }
        };
        let diagnostics = if mode == "env_probe" {
            std::env::vars().map(|(name, _)| name).collect()
        } else {
            Vec::new()
        };
        let response = AdapterMessage::Result {
            schema_version: PROTOCOL_VERSION.into(),
            request_id: if mode == "wrong_id" {
                format!("wrong-{request_id}")
            } else {
                request_id
            },
            native: NativeResponse {
                label: label.into(),
                confidence_permille: Some(800),
                evidence: Vec::new(),
                diagnostics,
                abstained: mode == "abstain",
                remote_requests: 0,
                declared_cost_microusd: 0,
            },
        };
        send(&mut output, &response)?;
        if mode == "duplicate" {
            send(&mut output, &response)?;
        }
    }
    Ok(())
}

fn send(
    output: &mut impl Write,
    message: &AdapterMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    serde_json::to_writer(&mut *output, message)?;
    output.write_all(b"\n")?;
    output.flush()?;
    Ok(())
}
