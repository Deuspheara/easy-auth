use super::setup::ClientFixture;
use crate::*;
use serde_json::json;
use std::sync::atomic::Ordering;
use uuid::Uuid;

fn native(f: &ClientFixture) -> OidcClient {
    let config = OidcClientConfiguration::native(
        "https://issuer.example",
        Uuid::new_v4(),
        "127.0.0.1:49152".parse().unwrap(),
        "/callback",
        true,
    )
    .unwrap();
    OidcClient::new(config, f.provider.http.clone(), f.post.clone()).unwrap()
}
fn credentials() -> serde_json::Value {
    json!({"access_token":Secret::generate().unwrap().expose(), "token_type":"Bearer",
        "expires_in":60,"scope":"openid offline_access", "refresh_token":Secret::generate().unwrap().expose(), "refresh_expires_in":3600})
}
#[tokio::test]
async fn native_refresh_returns_only_new_credentials_and_posts_once() {
    let f = ClientFixture::new();
    let native = native(&f);
    let wire = credentials();
    *f.post.body.lock().unwrap() = serde_json::to_vec(&wire).unwrap();
    let old = Secret::generate().unwrap();
    let result = native
        .refresh(OidcClientCredential::parse(old.expose().into()).unwrap())
        .await
        .unwrap();
    assert_eq!(
        result.access_token().expose(),
        wire["access_token"].as_str().unwrap()
    );
    assert_eq!(
        result.refresh_token().unwrap().expose(),
        wire["refresh_token"].as_str().unwrap()
    );
    assert!(result.refresh_expires_us().unwrap() > result.access_expires_us());
    let seen = f.post.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    let fields: std::collections::BTreeMap<_, _> =
        url::form_urlencoded::parse(seen[0].form.as_bytes())
            .into_owned()
            .collect();
    assert_eq!(fields.len(), 3);
    assert_eq!(fields["grant_type"], "refresh_token");
    assert_eq!(fields["refresh_token"], old.expose());
    assert!(seen[0].authorization.is_none());
}
#[tokio::test]
async fn refresh_rejects_wrong_profile_and_ambiguous_failure_is_not_retried() {
    let f = ClientFixture::new();
    assert!(matches!(
        f.client
            .refresh(OidcClientCredential::parse("owned-credential".into()).unwrap())
            .await,
        Err(OidcClientError::Configuration)
    ));
    assert_eq!(f.post.posts(), 0);
    let native = native(&f);
    f.post.fail.store(true, Ordering::SeqCst);
    assert!(matches!(
        native
            .refresh(OidcClientCredential::parse("owned-credential".into()).unwrap())
            .await,
        Err(OidcClientError::Unavailable)
    ));
    assert_eq!(f.post.posts(), 1);
}
#[tokio::test]
async fn refresh_rejects_missing_replacement_and_identity_fields() {
    for field in ["refresh_token", "refresh_expires_in", "id_token"] {
        let f = ClientFixture::new();
        let native = native(&f);
        let mut wire = credentials();
        if field == "id_token" {
            wire[field] = json!("unexpected-identity");
        } else {
            wire.as_object_mut().unwrap().remove(field);
        }
        *f.post.body.lock().unwrap() = serde_json::to_vec(&wire).unwrap();
        assert!(matches!(
            native
                .refresh(OidcClientCredential::parse("owned-credential".into()).unwrap())
                .await,
            Err(OidcClientError::Protocol)
        ));
        assert_eq!(f.post.posts(), 1);
    }
}
