use please_judge::{Judge, Resolution, ReviewAuthority};
fn judge(endpoint: &str, key: &str) -> Judge {
    Judge::new(Resolution::resolve(|name| match name {
        "ANTHROPIC_BASE_URL" => Some(endpoint.into()),
        "ANTHROPIC_API_KEY" => Some(key.into()),
        _ => None,
    }))
}
#[test]
fn request_identity_tracks_endpoint_and_policy_without_publishing_credentials() {
    let a = judge(
        "https://example.invalid/private-route?token=private-query",
        "secret-a",
    )
    .inference_metadata();
    let b = judge(
        "https://example.invalid/private-route?token=private-query",
        "secret-b",
    )
    .inference_metadata();
    assert_eq!(a, b);
    for secret in ["secret-a", "private-query", "private-route"] {
        assert!(!a.to_string().contains(secret));
    }
    let other = judge("https://other.invalid", "secret-a").inference_metadata();
    assert_ne!(a["endpoint_sha256"], other["endpoint_sha256"]);
    let release = judge(
        "https://example.invalid/private-route?token=private-query",
        "secret-a",
    )
    .with_authority(ReviewAuthority::MayRelease)
    .inference_metadata();
    assert_ne!(a["authority"], release["authority"]);
    assert_eq!(
        a["ordinary_recipe_sha256"],
        release["ordinary_recipe_sha256"]
    );
}

#[test]
fn acceptance_contract_is_versioned_separately_from_request_recipes() {
    let metadata = judge("https://example.invalid", "secret").inference_metadata();
    assert_eq!(metadata["response_acceptance_version"], "2026-09-12.1");
    assert_eq!(metadata["ordinary_max_response_bytes"], 10 * 1024 * 1024);
    assert_eq!(metadata["ml_max_response_bytes"], 64 * 1024);
}
