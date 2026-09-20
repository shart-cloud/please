use please_core::context::{Boundary, BoundaryKind, ContextCompleteness};
use please_core::{CallerContext, InputProvenance};
use please_judge::jev::{JevRequest, Relation, MAX_INPUT_BYTES, MAX_RESPONSE_BYTES};
use serde_json::json;

fn context() -> CallerContext {
    CallerContext {
        task_context: Some("Read the release notes; do not change files.".into()),
        boundaries: vec![Boundary {
            kind: BoundaryKind::ToolActions,
            scope: "release.md".into(),
            constraint: "Read only. Writing is forbidden.".into(),
        }],
        context_completeness: ContextCompleteness {
            relevant: vec![BoundaryKind::ToolActions],
            known: vec![BoundaryKind::ToolActions],
            unavailable: vec![],
        },
    }
}
fn request() -> JevRequest {
    JevRequest::assemble(
        b"Write release.md.",
        &context(),
        InputProvenance::UserInput,
        "jev-latest",
    )
    .unwrap()
}
fn response() -> serde_json::Value {
    json!({"model":"jev-latest","answers":{"relation":{"type":"choice","choice":"conflicting_instruction","probabilities":{"aligned_instruction":0.01,"conflicting_instruction":0.96,"non_instruction":0.01,"indeterminate":0.02},"confidence":0.9}},"usage":{"input_tokens":123,"output_tokens":20}})
}
#[test]
fn preserves_native_scores_without_release_authority() {
    let r = request();
    let advice = r.parse_response(&response().to_string()).unwrap();
    assert_eq!(advice.relation, Relation::ConflictingInstruction);
    assert_eq!(advice.authority, "advisory");
    assert_eq!(advice.probabilities.conflicting_instruction, 0.96);
    assert!(advice.evidence.is_empty());
    assert_eq!(advice.request_sha256, r.request_sha256());
}
#[test]
fn low_support_abstains() {
    let mut raw = response();
    raw["answers"]["relation"]["probabilities"] = json!({"aligned_instruction":0.2,"conflicting_instruction":0.4,"non_instruction":0.2,"indeterminate":0.2});
    assert_eq!(
        request().parse_response(&raw.to_string()).unwrap().relation,
        Relation::Indeterminate
    );
}
#[test]
fn incomplete_context_is_refused_before_network() {
    let mut c = context();
    c.context_completeness.known.clear();
    c.context_completeness.unavailable = vec![BoundaryKind::ToolActions];
    assert!(JevRequest::assemble(
        b"Read release.md.",
        &c,
        InputProvenance::UserInput,
        "jev-latest"
    )
    .is_err());
    c = context();
    c.task_context = None;
    assert!(JevRequest::assemble(b"x", &c, InputProvenance::UserInput, "jev-latest").is_err());
    assert!(
        JevRequest::assemble(b"x", &context(), InputProvenance::Unspecified, "jev-latest").is_err()
    );
}
#[test]
fn bounded_and_utf8_only() {
    assert!(JevRequest::assemble(
        &vec![b'x'; MAX_INPUT_BYTES + 1],
        &context(),
        InputProvenance::UserInput,
        "jev-latest"
    )
    .is_err());
    assert!(
        JevRequest::assemble(&[255], &context(), InputProvenance::UserInput, "jev-latest").is_err()
    );
    assert!(request()
        .parse_response(&" ".repeat(MAX_RESPONSE_BYTES + 1))
        .is_err());
}
#[test]
fn request_binds_input_and_context_and_does_not_send_detector_labels() {
    let r = request();
    let body: serde_json::Value = serde_json::from_str(r.body()).unwrap();
    assert_eq!(body["state"]["untrusted_candidate"], "Write release.md.");
    assert!(body["state"].get("ground_truth").is_none());
    let other = JevRequest::assemble(
        b"Read release.md.",
        &context(),
        InputProvenance::UserInput,
        "jev-latest",
    )
    .unwrap();
    assert_ne!(r.request_sha256(), other.request_sha256());
}
#[test]
fn malformed_or_inconsistent_answers_are_refused() {
    for path in ["choice", "type", "probabilities", "confidence"] {
        let mut raw = response();
        raw["answers"]["relation"]
            .as_object_mut()
            .unwrap()
            .remove(path);
        assert!(request().parse_response(&raw.to_string()).is_err());
    }
    let mut raw = response();
    raw["answers"]["relation"]["choice"] = json!("aligned_instruction");
    assert!(request().parse_response(&raw.to_string()).is_err());
    let mut raw = response();
    raw["answers"]["extra"] = json!({});
    assert!(request().parse_response(&raw.to_string()).is_err());
    let mut raw = response();
    raw["answers"]["relation"]["probabilities"]["aligned_instruction"] = json!(-0.1);
    assert!(request().parse_response(&raw.to_string()).is_err());
    let mut raw = response();
    raw["answers"]["relation"]["probabilities"]["aligned_instruction"] = json!(0.5);
    assert!(request().parse_response(&raw.to_string()).is_err());
}
#[test]
fn duplicate_fields_and_trailing_data_are_refused() {
    let raw = response().to_string();
    assert!(request()
        .parse_response(&raw.replace("\"model\":", "\"model\":\"spoof\",\"model\":"))
        .is_err());
    assert!(request().parse_response(&(raw + "{}")).is_err());
}
proptest::proptest! {
    #[test]
    fn arbitrary_provider_bytes_cannot_panic(raw in ".{0,4096}") {
        let _ = request().parse_response(&raw);
    }
}

#[test]
fn preserves_literal_resource_names_in_context() {
    let mut c = context();
    c.boundaries[0].scope = "a&b.md".into();
    let request = JevRequest::assemble(
        b"Read a&b.md.",
        &c,
        InputProvenance::UserInput,
        "jev-latest",
    )
    .unwrap();
    let body: serde_json::Value = serde_json::from_str(request.body()).unwrap();
    assert_eq!(
        body["state"]["caller_context"]["boundaries"][0]["scope"],
        "a&b.md"
    );
    assert_eq!(body["state"]["provenance"], "user_input");
}

#[test]
fn saved_advice_roundtrip_and_untrusted_metadata_rejection() {
    use please_judge::jev::JevAdvice;
    let advice = request().parse_response(&response().to_string()).unwrap();
    let original = serde_json::to_value(&advice).unwrap();
    let reopened = JevAdvice::from_saved_bytes(&serde_json::to_vec(&original).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(reopened).unwrap(), original);
    for (field, bad) in [
        ("schema_version", json!("unknown/v2")),
        ("authority", json!("release")),
        ("confidence", json!(1.1)),
        ("confidence", json!(-0.1)),
        ("remote_requests", json!(2)),
        ("remote_requests", json!(-1)),
        ("model", json!("jev\u{1b}[2J")),
        ("input_sha256", json!("spoof")),
        ("recipe_sha256", json!("g".repeat(64))),
        ("evidence", json!([null])),
        ("scores_calibrated_for_please", json!(true)),
        ("relation", json!("aligned_instruction")),
        ("native_choice", json!("non_instruction")),
    ] {
        let mut v = original.clone();
        v[field] = bad;
        assert!(
            JevAdvice::from_saved_bytes(&serde_json::to_vec(&v).unwrap()).is_err(),
            "{field}"
        );
    }
    for field in original.as_object().unwrap().keys() {
        let mut v = original.clone();
        v.as_object_mut().unwrap().remove(field);
        assert!(
            JevAdvice::from_saved_bytes(&serde_json::to_vec(&v).unwrap()).is_err(),
            "{field}"
        );
    }
    let raw = original.to_string();
    assert!(JevAdvice::from_saved_bytes(
        raw.replace("\"confidence\":", "\"confidence\":0.9,\"confidence\":")
            .as_bytes()
    )
    .is_err());
    let mut v = original.clone();
    v["probabilities"]["conflicting_instruction"] = json!(0.2);
    assert!(JevAdvice::from_saved_bytes(v.to_string().as_bytes()).is_err());
    v = original.clone();
    v["usage"]["input_tokens"] = json!(1.5);
    assert!(JevAdvice::from_saved_bytes(v.to_string().as_bytes()).is_err());
    assert!(JevAdvice::from_saved_bytes(&[0xff]).is_err());
    assert!(
        JevAdvice::from_saved_bytes(&vec![b' '; please_judge::jev::MAX_LOCAL_BYTES + 1]).is_err()
    );
}
#[test]
fn preset_roundtrip_keeps_all_boundary_kinds_and_unavailable_scopes() {
    use please_judge::jev::{JevPreset, PRESET_VERSION};
    let mut c = context();
    c.boundaries.push(Boundary {
        kind: BoundaryKind::ProtectedDataDestinations,
        scope: "internal report".into(),
        constraint: "No external destinations.".into(),
    });
    c.context_completeness
        .relevant
        .push(BoundaryKind::ProtectedDataDestinations);
    c.context_completeness
        .known
        .push(BoundaryKind::ProtectedDataDestinations);
    c.context_completeness
        .relevant
        .push(BoundaryKind::HiddenApplicationContext);
    c.context_completeness
        .unavailable
        .push(BoundaryKind::HiddenApplicationContext);
    let preset = JevPreset {
        schema_version: PRESET_VERSION.into(),
        name: "Review".into(),
        context: c.clone(),
        provenance: InputProvenance::ToolResponse,
    };
    let raw = serde_json::to_vec(&preset).unwrap();
    let parsed = JevPreset::from_bytes(&raw).unwrap();
    assert_eq!(parsed.context, c);
    assert!(
        JevRequest::assemble(b"example", &parsed.context, parsed.provenance, "jev-latest").is_err()
    );
    let original = serde_json::to_value(preset).unwrap();
    for (field, value) in [
        ("schema_version", json!("v0")),
        ("name", json!("")),
        ("name", json!("x".repeat(257))),
        ("provenance", json!("unspecified")),
        ("api_key", json!("unwanted")),
        ("candidate", json!("unwanted")),
    ] {
        let mut v = original.clone();
        v[field] = value;
        assert!(JevPreset::from_bytes(v.to_string().as_bytes()).is_err());
    }
    let mut v = original.clone();
    v["context"]["context_completeness"]["unavailable"] = json!(["tool_actions"]);
    assert!(JevPreset::from_bytes(v.to_string().as_bytes()).is_err());
    let raw = original.to_string();
    assert!(JevPreset::from_bytes(
        raw.replace("\"name\":", "\"name\":\"duplicate\",\"name\":")
            .as_bytes()
    )
    .is_err());
    assert!(JevPreset::from_bytes(&vec![b' '; please_judge::jev::MAX_LOCAL_BYTES + 1]).is_err());
}
proptest::proptest! {
    #[test]
    fn arbitrary_local_files_cannot_panic(raw in proptest::collection::vec(proptest::num::u8::ANY, 0..8192)) {
        let _ = please_judge::jev::JevAdvice::from_saved_bytes(&raw);
        let _ = please_judge::jev::JevPreset::from_bytes(&raw);
    }
}
