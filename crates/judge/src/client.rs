//! One synchronous `POST` (plan D2, R1).
//!
//! No async, no executor, no runtime. The requirement is one JSON `POST` to one endpoint with a timeout,
//! and `ureq` is blocking by design — adding tokio for a single request is the same weight objection that
//! ruled out `rig.rs`, one level down.
//!
//! # Structured output is a tool schema, not a request for JSON
//!
//! One tool is declared, its input schema *is* the answer space, and the model is required to call it
//! (R2). Three of the spec's requirements are much easier to hold this way:
//!
//! * **FR-405** wants no free-text field. A schema with `enum` constraints *is* that requirement, expressed
//!   where the model can see it, rather than a hope about formatting.
//! * **FR-409** wants non-conforming responses rejected rather than salvaged. A schema gives an unambiguous
//!   conformance test; prose parsing invites a lenient path.
//! * **FR-406** wants the prompt free of leading words. Moving the answer space into a schema shrinks the
//!   prompt, so there is less prose in which to accidentally name the interesting answer.
//!
//! The security argument is the stronger one: a model talked into ignoring its instructions can still only
//! emit a value the schema permits. **The blast radius of a captured judge is bounded by the enum.**
//!
//! A proxy that does not support tool use is `TierUnavailable`, never a fallback to prose parsing — falling
//! back would quietly move the conformance boundary from the schema into our parser.

use std::time::Duration;

use serde_json::{json, Value};

use crate::credential::{Resolution, API_VERSION};
use crate::request::{JudgeRequest, SYSTEM_PROMPT};

/// The name of the one tool the model may call.
///
/// Neutral, like everything else the model sees. Not `detect_injection`, not `assess_risk` — naming the
/// interesting answer produces it (FR-406).
pub const TOOL_NAME: &str = "classify_document";

/// Every way the transport can fail. All of them become `TierUnavailable` (FR-402).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    /// Nothing in the environment yielded a credential. Names the variables consulted, **never a value**
    /// (FR-413).
    NoCredential { consulted: String },
    /// The endpoint could not be reached, DNS failed, or the connection dropped.
    Unreachable { endpoint: String, detail: String },
    /// The per-invocation timeout expired (FR-420).
    TimedOut { seconds: u64 },
    /// A non-2xx status. The body is **deliberately not included**: the body of a 401 can echo the token
    /// that was sent, and the natural way to write this error is to include it (plan D3, rule 1).
    Status { code: u16 },
    /// A 2xx whose body was not JSON, or was JSON in an unexpected shape.
    UnreadableBody { detail: String },
}

impl std::fmt::Display for TransportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCredential { consulted } => {
                write!(
                    f,
                    "no credential in the environment (consulted: {consulted})"
                )
            }
            Self::Unreachable { endpoint, detail } => {
                write!(f, "{endpoint} could not be reached: {detail}")
            }
            Self::TimedOut { seconds } => write!(f, "no response within {seconds}s"),
            Self::Status { code } => write!(f, "endpoint returned HTTP {code}"),
            Self::UnreadableBody { detail } => write!(f, "response body unusable: {detail}"),
        }
    }
}

/// The tool declaration: the whole answer space, as JSON Schema.
///
/// This mirrors `contracts/judge-response.schema.json`. It is spelled out here rather than loaded from that
/// file because the contract is a specification artifact and this is a wire payload — vendoring the file
/// into the binary would make an edit to a design document a silent change to what is sent.
fn tool_schema() -> Value {
    json!({
        "name": TOOL_NAME,
        "description": "Record the classification of the document and each excerpt.",
        "input_schema": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "addressed_to",
                "imperative_source",
                "framing",
                "stated_purpose_explains_content",
                "spans"
            ],
            "properties": {
                "addressed_to": {
                    "description": "Who the document speaks to.",
                    "enum": ["document_recipient", "processing_agent", "unclear"]
                },
                "imperative_source": {
                    "description": "Where any instruction in the document originates.",
                    "enum": ["document_author", "quoted_third_party", "none_present"]
                },
                "framing": {
                    "description": "How the document presents its own content.",
                    "enum": [
                        "presented_as_example",
                        "presented_as_data",
                        "presented_as_report",
                        "none"
                    ]
                },
                "stated_purpose_explains_content": {
                    "description": "Whether the document states a purpose that accounts for \
                                    instruction-shaped text being present.",
                    "enum": ["yes", "no", "unclear"]
                },
                "spans": {
                    "description": "One entry per excerpt, no more and no fewer.",
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["span_id", "span_role"],
                        "properties": {
                            "span_id": { "type": "string", "maxLength": 64 },
                            "span_role": {
                                "description": "What the excerpt is, as opposed to what it resembles.",
                                "enum": [
                                    "instruction",
                                    "description_of_an_instruction",
                                    "unrelated"
                                ]
                            }
                        }
                    }
                },
                "model_severity": {
                    "description": "Optional. Your own 0-100 rating, recorded for calibration.",
                    "type": "integer",
                    "minimum": 0,
                    "maximum": 100
                }
            }
        }
    })
}

/// Send the request and return the tool input the model produced.
///
/// Returns the raw tool input as a `Value`; validating it against the request is
/// [`crate::response::JudgeResponse::parse`]'s job, so that transport failures and schema failures cannot
/// be confused for one another in the gap detail.
pub fn send(
    resolution: &Resolution,
    request: &JudgeRequest,
    timeout: Duration,
) -> Result<Value, TransportError> {
    let Some(credential) = resolution.credential() else {
        return Err(TransportError::NoCredential {
            consulted: Resolution::consulted(),
        });
    };

    let body = json!({
        "model": resolution.model(),
        "max_tokens": 1024,
        // Narrows the non-determinism without closing it (plan D7). The honest position is that this tier
        // is outside SC-011 and says so in docs/limits.md, rather than that temperature 0 fixed it.
        "temperature": 0,
        "system": SYSTEM_PROMPT,
        "tools": [tool_schema()],
        // Required, not merely offered. A model that answers in prose has been talked to, and this is what
        // makes that a transport-level failure rather than something to parse around.
        "tool_choice": { "type": "tool", "name": TOOL_NAME },
        "messages": [{
            "role": "user",
            "content": request.user_content(),
        }],
    });

    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .into();

    let url = format!("{}/v1/messages", resolution.endpoint());
    let response = agent
        .post(&url)
        .header("anthropic-version", API_VERSION)
        .header("content-type", "application/json")
        .header(credential.source().header(), &credential.header_value())
        .send_json(&body);

    let mut response = match response {
        Ok(response) => response,
        Err(ureq::Error::StatusCode(code)) => return Err(TransportError::Status { code }),
        Err(ureq::Error::Timeout(_)) => {
            return Err(TransportError::TimedOut {
                seconds: timeout.as_secs(),
            })
        }
        Err(e) => {
            return Err(TransportError::Unreachable {
                endpoint: resolution.endpoint().to_string(),
                // `e` is a ureq error — a connection or protocol failure. It has never seen the request
                // headers, so it cannot contain the credential.
                detail: e.to_string(),
            });
        }
    };

    let parsed: Value =
        response
            .body_mut()
            .read_json()
            .map_err(|e| TransportError::UnreadableBody {
                detail: e.to_string(),
            })?;

    extract_tool_input(&parsed)
}

/// Pull the one tool call's input out of a Messages API response.
///
/// Anything else in `content` is ignored — a model may emit a text block before its tool call and that is
/// not a failure. What *is* a failure is no tool block at all, which per R2 is `TierUnavailable` rather
/// than an invitation to read the prose.
fn extract_tool_input(response: &Value) -> Result<Value, TransportError> {
    let content = response
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| TransportError::UnreadableBody {
            detail: "response has no content array".to_string(),
        })?;

    for block in content {
        if block.get("type").and_then(Value::as_str) == Some("tool_use")
            && block.get("name").and_then(Value::as_str) == Some(TOOL_NAME)
        {
            return block
                .get("input")
                .cloned()
                .ok_or_else(|| TransportError::UnreadableBody {
                    detail: "tool call carried no input".to_string(),
                });
        }
    }

    Err(TransportError::UnreadableBody {
        detail: format!(
            "the model did not call {TOOL_NAME}; a response in prose is not parsed as a fallback"
        ),
    })
}
