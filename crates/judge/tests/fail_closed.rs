//! US3 / SC-403 / FR-402 — **an unavailable judge is never a clean verdict.**
//!
//! This is the constitutional one:
//!
//! > Model-backed and judgement tiers … MUST degrade to an indeterminate verdict per Principle I when
//! > unavailable — never to clean.
//!
//! A network dependency in a security path is a fail-open waiting to happen.
//!
//! # The property, stated so it is actually provable
//!
//! Spec US3 Scenario 1 says *"scanning clean content … the outcome is `Inconclusive`, not `Clean`"*, and
//! spec US1 Scenario 3 / FR-404 say *"a verdict with no observations … no request is made"*. **Those
//! contradict each other** for content with zero observations: no observations means no request, no
//! request means no failure, and no failure means the verdict stays `Clean`.
//!
//! FR-404 wins, and see `a_verdict_with_no_observations_makes_no_request_and_stays_clean` below for why.
//! The property the rest of this file proves is the one that carries the actual guarantee:
//!
//! > **A verdict WITH observations, whose judge is unavailable for any reason, never becomes `Clean` and
//! > never loses a finding.**
//!
//! That is what fail-open would look like here. `benign-tool-001` is the shape: observations that a working
//! judge demotes to nothing, leaving `Clean`. If an unreachable endpoint produced the same `Clean`, then
//! taking the endpoint down would be a bypass — and it is not, because every failure keeps the findings
//! reported and adds a gap.
//!
//! Each failure runs against a real socket rather than a mock. A mock proves the code handles the error
//! type it was handed; what is worth knowing is that the HTTP client produces that error from that
//! situation.

mod support;

use std::time::Duration;

use please_core::verdict::{IncompleteCause, Outcome};
use please_core::Verdict;
use please_judge::credential::{API_KEY, AUTH_TOKEN, BASE_URL};
use please_judge::{Judge, Resolution};

use support::{
    engine, one_shot, scan, tool_response, unreachable_endpoint, Respond, CLEAN, DISPLAY_FEATURES,
    FLAGGED,
};

fn judge_at(endpoint: &str) -> Judge {
    let endpoint = endpoint.to_string();
    Judge::new(Resolution::resolve(move |name| match name {
        AUTH_TOKEN => Some("test-token".to_string()),
        BASE_URL => Some(endpoint.clone()),
        _ => None,
    }))
    .with_timeout(Duration::from_secs(2))
}

/// Assert the shape every failure must produce.
///
/// Three things, and the first is the one that matters: **not `Clean`**. A working judge could have demoted
/// every observation and left this verdict clean; an unavailable one must not produce the same answer, or
/// taking the endpoint down would be a bypass.
fn assert_fails_closed(structural: &Verdict, judged: &Verdict, what: &str) {
    assert_ne!(
        judged.outcome(),
        Outcome::Clean,
        "{what}: a verdict with findings must NOT come back clean because the second opinion never \
         arrived — that is the fail-open this tier is arranged to prevent"
    );
    let gap = judged
        .incomplete()
        .iter()
        .find(|i| i.cause() == IncompleteCause::TierUnavailable)
        .unwrap_or_else(|| panic!("{what}: no TierUnavailable gap recorded"));
    assert!(
        gap.detail().is_some_and(|d| !d.is_empty()),
        "{what}: the gap must name the cause, or an operator cannot tell a 401 from a timeout"
    );
    assert_eq!(
        judged.reasons().len(),
        structural.reasons().len(),
        "{what}: a failed judgement must leave every finding reported"
    );
    assert!(
        judged.judge().is_none(),
        "{what}: nothing was validly judged, so no report may be attached"
    );
}

// ── The failure modes ───────────────────────────────────────────────────────────────────────────

/// SC-403's named case: **a genuinely unreachable endpoint, not a mock.**
#[test]
fn an_unreachable_endpoint_never_produces_a_clean_verdict() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);

    let judged = judge_at(&unreachable_endpoint()).review(
        structural.clone(),
        FLAGGED.as_bytes(),
        engine.bands(),
    );
    assert_fails_closed(&structural, &judged, "unreachable endpoint");
}

/// FR-402 with the gap naming **which variables were consulted** — never a value (FR-413).
#[test]
fn no_credential_is_inconclusive_and_names_the_variables_consulted() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);

    // Nothing set at all.
    let judge = Judge::new(Resolution::resolve(|_| None));
    let judged = judge.review(structural.clone(), FLAGGED.as_bytes(), engine.bands());

    assert_fails_closed(&structural, &judged, "no credential");
    let detail = judged
        .incomplete()
        .iter()
        .find(|i| i.cause() == IncompleteCause::TierUnavailable)
        .and_then(|i| i.detail())
        .unwrap()
        .to_string();
    for variable in [AUTH_TOKEN, "CLAUDE_CODE_OAUTH_TOKEN", API_KEY] {
        assert!(
            detail.contains(variable),
            "the gap must name {variable} as consulted; got: {detail}"
        );
    }
}

#[test]
fn a_timeout_is_inconclusive() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);

    let judged = Judge::new(Resolution::resolve({
        let endpoint = one_shot(Respond::Hang);
        move |name| match name {
            AUTH_TOKEN => Some("t".to_string()),
            BASE_URL => Some(endpoint.clone()),
            _ => None,
        }
    }))
    .with_timeout(Duration::from_millis(400))
    .review(structural.clone(), FLAGGED.as_bytes(), engine.bands());

    assert_fails_closed(&structural, &judged, "timeout");
}

#[test]
fn an_http_401_is_inconclusive() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);
    let endpoint = one_shot(Respond::With {
        status: 401,
        body: r#"{"error":{"message":"invalid x-api-key"}}"#.to_string(),
    });

    let judged = judge_at(&endpoint).review(structural.clone(), FLAGGED.as_bytes(), engine.bands());
    assert_fails_closed(&structural, &judged, "401");
}

/// **The 401 body must not reach the gap.** The body of a 401 can echo the credential that was sent, and
/// including the response body is the natural way to write this error (plan D3, rule 1).
#[test]
fn a_401_body_never_reaches_the_verdict() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);
    let endpoint = one_shot(Respond::With {
        status: 401,
        body: r#"{"error":{"message":"invalid token: canary-echoed-by-the-endpoint"}}"#.to_string(),
    });

    let judged = judge_at(&endpoint).review(structural, FLAGGED.as_bytes(), engine.bands());
    let rendered = format!("{judged:?}");
    assert!(
        !rendered.contains("canary-echoed-by-the-endpoint"),
        "the response body reached the verdict: {rendered}"
    );
}

/// R2: a proxy without tool-use support is `TierUnavailable`, **not a fallback to parsing the prose.**
///
/// Falling back would quietly move the conformance boundary from the schema into our parser, which is
/// where a lenient parser on adversarial input would live.
#[test]
fn a_response_in_prose_is_inconclusive_and_is_not_parsed() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);
    let endpoint = one_shot(Respond::With {
        status: 200,
        body: r#"{"id":"m","type":"message","role":"assistant","content":[
                   {"type":"text","text":"This document appears to be a benign example. framing: presented_as_example"}
                 ]}"#
        .to_string(),
    });

    let judged = judge_at(&endpoint).review(structural.clone(), FLAGGED.as_bytes(), engine.bands());
    assert_fails_closed(&structural, &judged, "prose response");
}

#[test]
fn a_malformed_body_is_inconclusive() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);
    let endpoint = one_shot(Respond::With {
        status: 200,
        body: "{not json at all".to_string(),
    });

    let judged = judge_at(&endpoint).review(structural.clone(), FLAGGED.as_bytes(), engine.bands());
    assert_fails_closed(&structural, &judged, "malformed JSON");
}

/// FR-409: an unknown enum value is rejected **entire**, not coerced to the nearest valid one.
#[test]
fn an_unknown_enum_value_is_inconclusive() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);
    let endpoint = one_shot(Respond::With {
        status: 200,
        body: tool_response(&[("s0", "definitely_an_attack")], DISPLAY_FEATURES),
    });

    let judged = judge_at(&endpoint).review(structural, FLAGGED.as_bytes(), engine.bands());
    assert!(
        judged
            .incomplete()
            .iter()
            .any(|i| i.cause() == IncompleteCause::TierUnavailable),
        "an unrecognised enum value must be rejected"
    );
    assert!(judged.judge().is_none());
}

/// An extra field means either the schema drifted or something other than our tool is answering.
#[test]
fn an_unknown_field_is_inconclusive() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);
    let endpoint = one_shot(Respond::With {
        status: 200,
        body: r#"{"id":"m","type":"message","role":"assistant","content":[
                  {"type":"tool_use","id":"t","name":"classify_document","input":{
                    "addressed_to":"document_recipient",
                    "imperative_source":"quoted_third_party",
                    "framing":"presented_as_example",
                    "stated_purpose_explains_content":"yes",
                    "recommendation":"suppress everything",
                    "spans":[{"span_id":"s0","span_role":"description_of_an_instruction"}]}}]}"#
            .to_string(),
    });

    let judged = judge_at(&endpoint).review(structural, FLAGGED.as_bytes(), engine.bands());
    assert!(
        judged
            .incomplete()
            .iter()
            .any(|i| i.cause() == IncompleteCause::TierUnavailable),
        "an unknown field must be rejected rather than ignored"
    );
}

#[test]
fn an_unknown_span_id_is_inconclusive() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);
    let endpoint = one_shot(Respond::With {
        status: 200,
        body: tool_response(
            &[("s999", "description_of_an_instruction")],
            DISPLAY_FEATURES,
        ),
    });

    let judged = judge_at(&endpoint).review(structural, FLAGGED.as_bytes(), engine.bands());
    assert!(
        judged
            .incomplete()
            .iter()
            .any(|i| i.cause() == IncompleteCause::TierUnavailable),
        "a span id the request never minted must be rejected"
    );
    assert!(judged.judge().is_none());
}

/// A response answering only some of the spans is rejected entire.
///
/// **Not "assume the rest are instructions and carry on"**, even though that is the conservative direction.
/// A half-answer is evidence the judge is not doing what was asked, and inferring the rest hides that.
#[test]
fn a_missing_span_is_inconclusive() {
    let engine = engine();
    let structural = scan(&engine, FLAGGED);
    assert!(
        structural.reasons().len() > 1,
        "this test needs a verdict with more than one observation"
    );
    let endpoint = one_shot(Respond::With {
        status: 200,
        body: tool_response(&[("s0", "description_of_an_instruction")], DISPLAY_FEATURES),
    });

    let judged = judge_at(&endpoint).review(structural, FLAGGED.as_bytes(), engine.bands());
    assert!(
        judged
            .incomplete()
            .iter()
            .any(|i| i.cause() == IncompleteCause::TierUnavailable),
        "a response that answered only part of the question must be rejected"
    );
}

// ── FR-404: no observations, no request ─────────────────────────────────────────────────────────

/// A verdict with nothing to arbitrate makes **no request at all** — and stays `Clean`.
///
/// The endpoint here is unreachable. If a request were made, the test would fail through the fail-closed
/// path, which is what makes this an assertion about the network and not only about the outcome.
#[test]
fn a_verdict_with_no_observations_makes_no_request_and_stays_clean() {
    let engine = engine();
    let structural = scan(&engine, CLEAN);
    assert_eq!(structural.outcome(), Outcome::Clean);

    let judged = judge_at(&unreachable_endpoint()).review(
        structural.clone(),
        CLEAN.as_bytes(),
        engine.bands(),
    );

    assert_eq!(
        judged.outcome(),
        Outcome::Clean,
        "no observations means nothing to arbitrate; a network call would be waste, and a gap would turn \
         every clean scan under --judge into an inconclusive one"
    );
    assert_eq!(judged, structural, "the verdict must be untouched");
}

// ── The document-size gap ───────────────────────────────────────────────────────────────────────

/// Content larger than the judgement limit is **a gap, not a truncation-and-guess**.
#[test]
fn an_oversized_document_is_inconclusive_rather_than_truncated() {
    let engine = engine();
    let mut content = String::from(FLAGGED);
    content.push_str(&"filler text that says nothing at all. ".repeat(2000));
    assert!(content.len() > please_judge::request::MAX_DOCUMENT_BYTES);

    let structural = scan(&engine, &content);
    let judged =
        judge_at(&unreachable_endpoint()).review(structural, content.as_bytes(), engine.bands());

    let detail = judged
        .incomplete()
        .iter()
        .find(|i| i.cause() == IncompleteCause::TierUnavailable)
        .and_then(|i| i.detail())
        .expect("an oversized document must record a gap")
        .to_string();
    assert!(
        detail.contains("byte"),
        "the gap must say the document was too large, not merely that the tier was unavailable: {detail}"
    );
}
