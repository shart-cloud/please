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
pub const TOOL_NAME: &str = crate::envelope::STRUCTURAL.tool_name;

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
/// Public so an experiment can compare a candidate schema against the shipping one.
///
/// This mirrors `contracts/judge-response.schema.json`. It is spelled out here rather than loaded from that
/// file because the contract is a specification artifact and this is a wire payload — vendoring the file
/// into the binary would make an edit to a design document a silent change to what is sent.
pub fn tool_schema() -> Value {
    json!({
        "name": TOOL_NAME,
        // ── THIS SENTENCE IS THE TIER ────────────────────────────────────────────────────────────
        //
        // It reads like boilerplate and it decides whether the feature works. Measured, 3/3 both ways:
        //
        //   "…of the document and each excerpt."   indirect-tool-003 → is_what_the_document_shows   0/3
        //   "…of each excerpt, then of the document."                → incidental_to_…              3/3
        //
        // Naming the document first establishes a frame — the model characterises the whole transcript as
        // "presenting data", and then every excerpt inside it is, correctly and uselessly, part of what it
        // shows. Asked about the excerpts FIRST, each one is judged on its own terms and the payload riding
        // inside grep output is recognised as a passenger.
        //
        // This is D4's own thesis one level down. D4 says naming the interesting answer produces it; this
        // says naming the interesting SCALE produces it. `tests/axis_probe.rs::ablate_the_shipping_schema`
        // is the measurement, and it is the only variant of five that fixed the tier.
        //
        // If T039 goes red, read this before touching score.rs.
        "description": "Record the classification of each excerpt, then of the document.",
        "input_schema": {
            "type": "object",
            "additionalProperties": false,
            // `spans` first, matching the description above. **Measured NOT to matter on its own**
            // (`axis_probe.rs::is_the_required_order_load_bearing_too`: 4/4 either way once the
            // description is corrected) — kept because agreeing with the sentence that does matter costs
            // nothing, and disagreeing with it would be a puzzle for the next reader.
            //
            // An earlier version of this comment claimed the order WAS load-bearing. It was written after
            // reordering and before measuring, and it was wrong. Recorded because the same mistake in the
            // spec is what this feature keeps finding.
            "required": [
                "spans",
                "addressed_to",
                "imperative_source",
                "framing",
                "stated_purpose_explains_content"
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
                        "required": ["span_id", "span_role", "span_relation_to_document"],
                        "properties": {
                            "span_id": { "type": "string", "maxLength": 64 },
                            "span_role": {
                                "description": "What the excerpt is, as opposed to what it resembles.",
                                "enum": [
                                    "instruction",
                                    "description_of_an_instruction",
                                    "unrelated"
                                ]
                            },
                            "span_relation_to_document": {
                                "description": "Whether this excerpt is part of what the document set \
                                                out to show, or incidental to it.",
                                "enum": [
                                    "is_what_the_document_shows",
                                    "incidental_to_what_the_document_shows",
                                    "unclear"
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

/// Compatibility helper returning decoded tool input after envelope acceptance.
///
/// A `Value` cannot retain duplicate payload fields. Shipping review uses [`send_captured`]
/// followed by [`JudgeRequest::parse_envelope`] to validate the raw response against its request.
pub fn send(
    resolution: &Resolution,
    request: &JudgeRequest,
    timeout: Duration,
) -> Result<Value, TransportError> {
    send_with_schema(resolution, tool_schema(), &request.user_content(), timeout)
}

/// Send a structural request with a supplied schema. Alternate schemas are for calibration experiments.
///
/// Public because `tests/axis_probe.rs` has to ask candidate questions the shipping schema does not
/// contain, and the alternative — exposing the credential value so a test could build its own request —
/// would put a hole in FR-413 for the sake of an experiment. The value's only exit stays
/// `Credential::header_value`, which is still `pub(crate)`.
///
/// Shipping callers retain raw envelopes and use [`JudgeRequest::parse_envelope`].
/// This compatibility helper checks the envelope, but converting input to `Value` loses duplicate fields.
/// Experimental schemas must supply their own validation before any result reaches a verdict.
pub fn send_with_schema(
    resolution: &Resolution,
    schema: Value,
    user_content: &str,
    timeout: Duration,
) -> Result<Value, TransportError> {
    let raw = send_with_schema_captured(resolution, schema, user_content, timeout)?;
    let input = crate::envelope::accept(&raw, &crate::envelope::STRUCTURAL).map_err(|detail| {
        TransportError::UnreadableBody {
            detail: detail.into(),
        }
    })?;
    serde_json::from_str(input.get()).map_err(|_| TransportError::UnreadableBody {
        detail: "malformed judge tool input".into(),
    })
}

/// Capture the exact baseline tool response without changing its prompt, schema, or request assembly.
/// Store raw bodies privately, along with request hashes and transport failures.
pub fn send_captured(
    resolution: &Resolution,
    request: &JudgeRequest,
    timeout: Duration,
) -> Result<String, TransportError> {
    send_with_schema_captured(resolution, tool_schema(), &request.user_content(), timeout)
}

pub(crate) fn send_with_schema_captured(
    resolution: &Resolution,
    schema: Value,
    user_content: &str,
    timeout: Duration,
) -> Result<String, TransportError> {
    let mut body = ordinary_recipe(resolution, schema);
    body["messages"] = json!([{"role": "user", "content": user_content}]);

    send_body(
        resolution,
        &body,
        timeout,
        crate::envelope::STRUCTURAL.max_bytes as u64,
    )
}

/// Exact successful response body for private evaluation capture. Never written into a verdict.
/// HTTP/status failures remain errors so an evaluator can retain them in its denominator.
pub fn send_ml_review(
    resolution: &Resolution,
    request: &crate::ml_review::MlReviewRequest,
    timeout: Duration,
) -> Result<String, TransportError> {
    let mut body = ml_recipe(resolution);
    body["messages"] = json!([{"role": "user", "content": request.user_content()}]);

    send_body(
        resolution,
        &body,
        timeout,
        crate::ml_review::MAX_RESPONSE_BYTES as u64,
    )
}

fn send_body(
    resolution: &Resolution,
    body: &Value,
    timeout: Duration,
    limit: u64,
) -> Result<String, TransportError> {
    let Some(credential) = resolution.credential() else {
        return Err(TransportError::NoCredential {
            consulted: Resolution::consulted(),
        });
    };

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
        .send_json(body);

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

    // ureq's reader errors when it reaches its limit before checking EOF. Reserve one byte
    // for that check, then enforce the same inclusive byte bound as captured parsing.
    let raw = response
        .body_mut()
        .with_config()
        .limit(limit + 1)
        .read_to_string()
        .map_err(|_| TransportError::UnreadableBody {
            detail: "unreadable or oversized response body".into(),
        })?;
    if raw.len() as u64 > limit {
        return Err(TransportError::UnreadableBody {
            detail: "unreadable or oversized response body".into(),
        });
    }
    Ok(raw)
}

fn ordinary_recipe(resolution: &Resolution, schema: Value) -> Value {
    json!({"model": resolution.model(), "max_tokens": 1024, "temperature": 0,
        "system": SYSTEM_PROMPT, "tools": [schema],
        "tool_choice": {"type": "tool", "name": TOOL_NAME}})
}
fn ml_recipe(resolution: &Resolution) -> Value {
    json!({"model": resolution.model(), "max_tokens": 8192, "temperature": 0,
        "system": crate::ml_review::SYSTEM_PROMPT, "tools": [crate::ml_review::tool_schema()],
        "tool_choice": {"type": "tool", "name": crate::ml_review::TOOL_NAME}})
}

pub(crate) fn inference_metadata(resolution: &Resolution) -> Value {
    use sha2::{Digest, Sha256};
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    // Hash the full resolved endpoint: URL credentials, paths and queries need not be published.
    json!({"model": resolution.model(),
        "endpoint_sha256": digest(resolution.endpoint().as_bytes()),
        "ordinary_recipe_sha256": digest(ordinary_recipe(resolution, tool_schema()).to_string().as_bytes()),
        "ml_recipe_sha256": digest(ml_recipe(resolution).to_string().as_bytes()),
        "prompt_version": crate::request::PROMPT_VERSION,
        "ml_contract_version": crate::ml_review::CONTRACT_VERSION,
        "response_acceptance_version": crate::envelope::VERSION,
        "ordinary_max_response_bytes": crate::envelope::STRUCTURAL.max_bytes,
        "ml_max_response_bytes": crate::envelope::ML.max_bytes,
        "temperature": 0, "ordinary_max_tokens": 1024, "ml_max_tokens": 8192,
        "remote_weights": "provider-controlled-unrecorded"})
}
