use super::setup::{ClientFixture, callback, parameters};
use crate::*;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::sync::atomic::Ordering;

#[tokio::test]
async fn discovery_pkce_and_normal_signature_complete_without_provider_cookie() {
    let f = ClientFixture::new();
    let pending = f.client.authorize().await.unwrap();
    let parameters = parameters(&pending);
    assert_eq!(parameters["client_id"], f.id.to_string());
    assert_eq!(parameters["scope"], "openid");
    assert_eq!(parameters["code_challenge_method"], "S256");
    assert_eq!(
        parameters["redirect_uri"],
        "https://rp.example/callback?tenant=one"
    );
    f.success(&pending);
    let callback = callback(&pending);
    let tokens = f.client.complete(pending, callback.as_str()).await.unwrap();
    assert_eq!(tokens.identity().issuer(), "https://issuer.example");
    assert_eq!(tokens.identity().client(), f.id);
    assert_eq!(tokens.identity().subject(), "pairwise-subject");
    assert!(tokens.identity().authenticated_at().is_some());
    assert!(tokens.refresh_token().is_none());
    assert!(tokens.refresh_expires_us().is_none());
    assert!(!tokens.access_token().expose().is_empty());
    let seen = f.post.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].url, "https://issuer.example/token");
    assert!(seen[0].authorization.is_none());
    let form: std::collections::BTreeMap<_, _> =
        url::form_urlencoded::parse(seen[0].form.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["client_id"], f.id.to_string());
    assert_eq!(form["redirect_uri"], parameters["redirect_uri"]);
    assert_eq!(
        form["code"],
        callback.query_pairs().find(|(k, _)| k == "code").unwrap().1
    );
    let verifier = Secret::parse(form["code_verifier"].clone()).unwrap();
    assert_eq!(
        URL_SAFE_NO_PAD.encode(verifier.verifier()),
        parameters["code_challenge"]
    );
    assert_eq!(f.provider.store.checks.load(Ordering::SeqCst), 0);
}

#[tokio::test]
async fn token_errors_are_typed_and_codes_are_not_retried() {
    for (status, error, expected) in [
        (400, "invalid_grant", OidcClientError::InvalidGrant),
        (401, "invalid_client", OidcClientError::InvalidClient),
        (429, "temporarily_unavailable", OidcClientError::RateLimited),
        (503, "temporarily_unavailable", OidcClientError::Unavailable),
    ] {
        let f = ClientFixture::new();
        let pending = f.client.authorize().await.unwrap();
        let callback = callback(&pending);
        f.post.status.store(status, Ordering::SeqCst);
        *f.post.body.lock().unwrap() =
            serde_json::to_vec(&serde_json::json!({"error":error})).unwrap();
        assert!(
            matches!(f.client.complete(pending, callback.as_str()).await, Err(e) if e == expected)
        );
        assert_eq!(f.post.posts(), 1);
    }
}

#[tokio::test]
async fn ambiguous_transport_failure_does_not_retry_code() {
    let f = ClientFixture::new();
    let pending = f.client.authorize().await.unwrap();
    let callback = callback(&pending);
    f.post.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        f.client.complete(pending, callback.as_str()).await,
        Err(OidcClientError::Unavailable)
    ));
    assert_eq!(f.post.posts(), 1);
}

#[tokio::test]
async fn noncacheable_documents_are_refetched_for_each_independent_operation() {
    let f = ClientFixture::new();
    f.provider.http.cache_seconds.store(0, Ordering::SeqCst);
    for expected_gets in [3, 6] {
        let pending = f.client.authorize().await.unwrap();
        let callback = callback(&pending);
        f.success(&pending);
        assert!(f.client.complete(pending, callback.as_str()).await.is_ok());
        assert_eq!(f.provider.gets(), expected_gets);
    }
    assert_eq!(f.post.posts(), 2);
}
