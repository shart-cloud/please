//! US4 — credentials resolve predictably and never leak (FR-411 through FR-415, SC-404).
//!
//! Every combination of the four variables, none of them touching the process environment.
//! `Resolution::resolve` takes a lookup precisely so these can be deterministic: `std::env::set_var`
//! mutates state shared by every thread in the test binary, and a suite that sets variables to test
//! precedence is a suite whose results depend on scheduling.

use please_judge::credential::{
    Ignored, API_KEY, AUTH_TOKEN, BASE_URL, DEFAULT_ENDPOINT, DEFAULT_MODEL, MODEL, OAUTH_TOKEN,
};
use please_judge::{CredentialSource, Resolution};

/// Build a lookup from a list of pairs. Anything absent from the list is unset.
fn env(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
    let owned: Vec<(String, String)> = pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();
    move |name: &str| {
        owned
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.clone())
    }
}

fn ignored_and_set(resolution: &Resolution) -> Vec<CredentialSource> {
    resolution
        .ignored()
        .iter()
        .filter(|i: &&Ignored| i.was_set)
        .map(|i| i.source)
        .collect()
}

// ── FR-413 / SC-404: the value cannot be printed ────────────────────────────────────────────────

/// T020. The natural way to write an error includes the thing that failed, and the thing that failed
/// here holds a secret.
#[test]
fn debug_on_a_credential_cannot_emit_its_value() {
    let secret = "sk-ant-canary-do-not-log-0123456789";
    let resolution = Resolution::resolve(env(&[(AUTH_TOKEN, secret)]));
    let credential = resolution.credential().expect("a credential was set");

    let debug = format!("{credential:?}");
    assert!(
        !debug.contains(secret),
        "Debug emitted the credential value: {debug}"
    );
    assert!(
        !debug.contains("canary"),
        "Debug emitted part of the credential value: {debug}"
    );
    assert!(
        debug.contains(AUTH_TOKEN),
        "Debug must still name the variable it came from, or a failure is undiagnosable: {debug}"
    );
}

/// The whole `Resolution` is `Debug` too, and it contains the credential. One `{:?}` on the outer type
/// must not do what a `{:?}` on the inner one refuses to.
#[test]
fn debug_on_the_whole_resolution_cannot_emit_a_value_either() {
    let secret = "sk-ant-canary-do-not-log-0123456789";
    let resolution = Resolution::resolve(env(&[
        (AUTH_TOKEN, secret),
        (API_KEY, "sk-ant-second-canary-9876543210"),
        (BASE_URL, "https://proxy.internal.example"),
    ]));

    let debug = format!("{resolution:?}");
    assert!(
        !debug.contains("canary"),
        "Resolution Debug leaked: {debug}"
    );
}

/// The diagnostic an operator actually reads. Everything in it is a variable name or an endpoint.
#[test]
fn the_check_diagnostic_contains_no_value() {
    let resolution = Resolution::resolve(env(&[
        (AUTH_TOKEN, "canary-auth"),
        (API_KEY, "canary-key"),
        (BASE_URL, "https://proxy.internal.example"),
        (MODEL, "claude-opus-4-1"),
    ]));

    let described = resolution.describe();
    assert!(
        !described.contains("canary"),
        "--check leaked a credential:\n{described}"
    );
    assert!(described.contains(AUTH_TOKEN));
    assert!(described.contains(API_KEY));
    assert!(described.contains("https://proxy.internal.example"));
    assert!(described.contains("claude-opus-4-1"));
}

/// Drive the **process environment** path and print everything it produces.
///
/// This test asserts almost nothing, and that is deliberate — it exists to make `ci/check-no-credential-leak.sh`
/// non-vacuous. That script runs the suite with canary values in the environment and greps the output; if
/// no test ever calls [`Resolution::from_env`], the canary reaches no code path and the grep passes without
/// having checked anything.
///
/// Found by mutation: leaking the value from `Debug` on purpose did **not** fail the script, because every
/// other test in this file supplies its own values through a closure. A check that cannot fail is not a
/// check.
///
/// So this prints the two renderings a credential could plausibly escape through — the diagnostic an
/// operator reads, and the `{:?}` someone adds while debugging — using whatever is really in the
/// environment. Locally that is usually a developer's own credentials, which is the point: the script's
/// canaries take the same path.
#[test]
fn the_process_environment_path_is_exercised_so_the_leak_check_is_not_vacuous() {
    let resolution = Resolution::from_env();

    println!("from_env describe:\n{}", resolution.describe());
    println!("from_env debug: {resolution:?}");
    if let Some(credential) = resolution.credential() {
        println!("from_env credential debug: {credential:?}");
    }

    // The one thing worth asserting: whatever the environment held, the endpoint resolved to something.
    assert!(!resolution.endpoint().is_empty());
}

// ── FR-411: resolution order, unconditionally ───────────────────────────────────────────────────

/// **The case the order exists for** (plan D3), and the one observed in a real Claude Code session.
///
/// Two credentials set at once with a non-default endpoint. Choosing `ANTHROPIC_API_KEY` would take an
/// upstream Anthropic account credential and send it as `x-api-key` to a third-party host. That is a
/// disclosure bug, not a 401.
#[test]
fn the_auth_token_wins_over_an_api_key_at_a_proxy_endpoint() {
    let resolution = Resolution::resolve(env(&[
        (AUTH_TOKEN, "proxy-scoped-token"),
        (API_KEY, "sk-ant-upstream-account-key"),
        (BASE_URL, "https://proxy.internal.example"),
    ]));

    let credential = resolution.credential().expect("a credential resolves");
    assert_eq!(credential.source(), CredentialSource::AuthToken);
    assert_eq!(credential.source().header(), "authorization");
    assert!(credential.source().is_bearer());
    assert_eq!(ignored_and_set(&resolution), vec![CredentialSource::ApiKey]);
    assert!(
        resolution.warnings().is_empty(),
        "an auth token at a proxy is the intended configuration; warning about it would train people \
         to ignore warnings"
    );
}

/// **The row the whole D3 argument turns on.** A bearer token with the DEFAULT endpoint.
///
/// A conditional rule — prefer the auth token only when a base URL is also set — would fall through here
/// and, with nothing else set, report no credential at all while holding one. "I set the token and it
/// ignored it" is the harder failure to diagnose and the worse one to ship.
#[test]
fn the_auth_token_is_used_at_the_default_endpoint_too() {
    let resolution = Resolution::resolve(env(&[(AUTH_TOKEN, "a-token")]));
    assert_eq!(
        resolution.credential().map(|c| c.source()),
        Some(CredentialSource::AuthToken)
    );
    assert_eq!(resolution.endpoint(), DEFAULT_ENDPOINT);
}

#[test]
fn the_oauth_token_outranks_an_api_key() {
    let resolution = Resolution::resolve(env(&[(OAUTH_TOKEN, "oauth"), (API_KEY, "key")]));
    let credential = resolution.credential().expect("a credential resolves");
    assert_eq!(credential.source(), CredentialSource::OauthToken);
    assert!(credential.source().is_bearer());
    assert_eq!(ignored_and_set(&resolution), vec![CredentialSource::ApiKey]);
}

#[test]
fn an_api_key_is_used_when_it_is_the_only_one() {
    let resolution = Resolution::resolve(env(&[(API_KEY, "key")]));
    let credential = resolution.credential().expect("a credential resolves");
    assert_eq!(credential.source(), CredentialSource::ApiKey);
    assert_eq!(credential.source().header(), "x-api-key");
    assert!(!credential.source().is_bearer());
}

/// All three at once. The order is total, so there is exactly one answer.
#[test]
fn all_three_set_resolves_to_the_most_specifically_scoped() {
    let resolution = Resolution::resolve(env(&[
        (AUTH_TOKEN, "a"),
        (OAUTH_TOKEN, "b"),
        (API_KEY, "c"),
        (BASE_URL, "https://proxy.internal.example"),
    ]));
    assert_eq!(
        resolution.credential().map(|c| c.source()),
        Some(CredentialSource::AuthToken)
    );
    assert_eq!(
        ignored_and_set(&resolution),
        vec![CredentialSource::OauthToken, CredentialSource::ApiKey]
    );
}

#[test]
fn no_credential_at_all_resolves_to_none_and_names_what_was_consulted() {
    let resolution = Resolution::resolve(env(&[]));
    assert!(resolution.credential().is_none());
    assert_eq!(resolution.ignored().len(), 3, "all three were consulted");
    assert!(resolution.ignored().iter().all(|i| !i.was_set));

    let consulted = Resolution::consulted();
    for variable in [AUTH_TOKEN, OAUTH_TOKEN, API_KEY] {
        assert!(
            consulted.contains(variable),
            "the failure message must name {variable}"
        );
    }
}

/// `FOO=` is how a shell blanks a variable it cannot `unset`. Treating it as set would send an empty
/// bearer token and produce a 401 whose cause is invisible in the diagnostic.
#[test]
fn an_empty_variable_is_treated_as_unset() {
    let resolution = Resolution::resolve(env(&[(AUTH_TOKEN, "   "), (API_KEY, "real")]));
    assert_eq!(
        resolution.credential().map(|c| c.source()),
        Some(CredentialSource::ApiKey),
        "a blank token must not shadow a real key"
    );
}

// ── FR-412: endpoint and model overrides ────────────────────────────────────────────────────────

#[test]
fn the_endpoint_and_model_default_when_unset() {
    let resolution = Resolution::resolve(env(&[(API_KEY, "k")]));
    assert_eq!(resolution.endpoint(), DEFAULT_ENDPOINT);
    assert_eq!(resolution.model(), DEFAULT_MODEL);
}

#[test]
fn the_endpoint_and_model_are_overridden_by_their_variables() {
    let resolution = Resolution::resolve(env(&[
        (AUTH_TOKEN, "t"),
        (BASE_URL, "https://proxy.internal.example/"),
        (MODEL, "claude-opus-4-1"),
    ]));
    assert_eq!(
        resolution.endpoint(),
        "https://proxy.internal.example",
        "a trailing slash must be trimmed, or the request path becomes //v1/messages"
    );
    assert_eq!(resolution.model(), "claude-opus-4-1");
}

// ── FR-415: the non-default-host warning ────────────────────────────────────────────────────────

#[test]
fn an_api_key_bound_for_a_non_default_host_warns_before_the_request() {
    let resolution = Resolution::resolve(env(&[
        (API_KEY, "sk-ant-upstream-account-key"),
        (BASE_URL, "https://proxy.internal.example"),
    ]));

    assert_eq!(resolution.warnings().len(), 1);
    let warning = &resolution.warnings()[0];
    assert!(warning.contains(API_KEY));
    assert!(warning.contains("https://proxy.internal.example"));
    assert!(
        !warning.contains("sk-ant"),
        "the warning names the variable, never its value: {warning}"
    );
}

#[test]
fn an_api_key_at_the_default_host_does_not_warn() {
    let resolution = Resolution::resolve(env(&[(API_KEY, "k")]));
    assert!(
        resolution.warnings().is_empty(),
        "an Anthropic credential going to Anthropic is where it belongs"
    );
}
