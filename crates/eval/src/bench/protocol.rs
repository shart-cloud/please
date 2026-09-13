use serde::{Deserialize, Serialize};

use crate::bench::identity::hex_encode;
use crate::bench::model::{NativeResponse, Surface, TrustedContext};
use crate::Result;

pub const PROTOCOL_VERSION: &str = "please-bench-jsonl/v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostMessage {
    Handshake {
        schema_version: String,
        system_id: String,
        system_digest: String,
    },
    Case {
        schema_version: String,
        request_id: String,
        surface: Surface,
        candidate_encoding: String,
        candidate_hex: String,
        candidate_sha256: String,
        byte_length: u64,
        provenance: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        trusted_context: Option<TrustedContext>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AdapterMessage {
    Handshake {
        schema_version: String,
        system_id: String,
        system_digest: String,
        adapter_version: String,
    },
    Result {
        schema_version: String,
        request_id: String,
        native: NativeResponse,
    },
}

impl HostMessage {
    pub fn handshake(system_id: String, system_digest: String) -> Self {
        Self::Handshake {
            schema_version: PROTOCOL_VERSION.into(),
            system_id,
            system_digest,
        }
    }

    pub fn case(
        request_id: &str,
        surface: Surface,
        candidate: &[u8],
        candidate_sha256: &str,
        provenance: &str,
        trusted_context: Option<&TrustedContext>,
    ) -> Self {
        Self::Case {
            schema_version: PROTOCOL_VERSION.into(),
            request_id: request_id.into(),
            surface,
            candidate_encoding: "hex".into(),
            candidate_hex: hex_encode(candidate),
            candidate_sha256: candidate_sha256.into(),
            byte_length: candidate.len() as u64,
            provenance: provenance.into(),
            trusted_context: trusted_context.cloned(),
        }
    }
}

pub fn encode_case_request(
    request_id: &str,
    surface: Surface,
    candidate: &[u8],
    candidate_sha256: &str,
    provenance: &str,
    trusted_context: Option<&TrustedContext>,
) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&HostMessage::case(
        request_id,
        surface,
        candidate,
        candidate_sha256,
        provenance,
        trusted_context,
    ))?)
}
