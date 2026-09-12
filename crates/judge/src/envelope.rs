//! Acceptance of a complete provider response, before any payload becomes a JSON Value.
//! Provider metadata and prose carry no authority. Errors never include provider-controlled text.

use serde::Deserialize;
use serde_json::value::RawValue;

pub(crate) const VERSION: &str = "2026-09-12.1";

pub(crate) struct Contract {
    pub tool_name: &'static str,
    pub max_bytes: usize,
}

pub(crate) const STRUCTURAL: Contract = Contract {
    tool_name: "classify_document",
    max_bytes: 10 * 1024 * 1024,
};
pub(crate) const ML: Contract = Contract {
    tool_name: "review_instruction_boundaries",
    max_bytes: 64 * 1024,
};

#[derive(Deserialize)]
struct Envelope {
    stop_reason: String,
    content: Vec<ContentBlock>,
}

#[derive(Deserialize)]
struct ContentBlock {
    #[serde(rename = "type")]
    kind: String,
    name: Option<String>,
    input: Option<Box<RawValue>>,
}

/// Preserve payload field multiplicity for the route's strict schema decoder.
/// Known protocol fields are also decoded directly, so duplicates cannot be erased.
pub(crate) fn accept(raw: &str, contract: &Contract) -> Result<Box<RawValue>, &'static str> {
    if raw.len() > contract.max_bytes {
        return Err("judge response envelope exceeds the byte limit");
    }
    let envelope: Envelope =
        serde_json::from_str(raw).map_err(|_| "malformed judge response envelope")?;
    if envelope.stop_reason != "tool_use" {
        return Err("judge response did not finish tool use");
    }
    let mut calls = envelope
        .content
        .into_iter()
        .filter(|b| b.kind == "tool_use");
    let call = calls.next().ok_or("judge response has no tool call")?;
    if calls.next().is_some() || call.name.as_deref() != Some(contract.tool_name) {
        return Err("judge response requires exactly one expected tool call");
    }
    let input = call.input.ok_or("judge tool input is missing or null")?;
    if !input.get().trim_start().starts_with('{') {
        return Err("judge tool input must be an object");
    }
    Ok(input)
}
