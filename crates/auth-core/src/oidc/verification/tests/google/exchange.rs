use super::super::setup::TokenHttp;
use super::setup::*;
use crate::*;
use serde_json::json;
use std::sync::atomic::Ordering;
use zeroize::Zeroizing;

#[tokio::test]
async fn web_and_desktop_exchange_use_original_redirect_and_pkce_with_registered_method() {
    for desktop in [false, true] {
        for post in [false, true] {
            let f = fixture(desktop);
            let tokens = TokenHttp::new();
            let client = client(&f, tokens.clone(), authentication(post)).unwrap();
            let (exchange, claims) = f.exchange().await;
            let verifier = Zeroizing::new(exchange.proof().pkce_verifier().expose().to_owned());
            let original_code = Secret::generate().unwrap();
            tokens.success(&f, &claims);
            let identity = client
                .exchange(
                    exchange,
                    OidcAuthorizationCode::parse(original_code.expose().to_owned()).unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(identity.configuration(), &f.store.connection);
            assert_eq!(identity.subject(), "subject");
            assert!(identity.authenticated_at().is_none());
            assert_eq!(tokens.posts(), 1);
            let seen = tokens.seen.lock().unwrap();
            let seen = &seen[0];
            assert_eq!(seen.url, "https://oauth2.googleapis.com/token");
            let form: Vec<_> = url::form_urlencoded::parse(seen.form.as_bytes()).collect();
            let value = |name: &str| {
                form.iter()
                    .find(|(k, _)| k == name)
                    .map(|(_, v)| v.as_ref())
            };
            assert!(value("code_verifier") == Some(verifier.as_str()));
            assert!(value("code") == Some(original_code.expose()));
            assert_eq!(
                value("redirect_uri"),
                Some(if desktop {
                    "http://127.0.0.1:49153/callback"
                } else {
                    "https://app.example/callback"
                })
            );
            assert_eq!(value("grant_type"), Some("authorization_code"));
            assert_eq!(seen.authorization.is_none(), post);
            assert_eq!(value("client_secret").is_some(), post);
        }
    }
}

#[tokio::test]
async fn provider_errors_remain_distinct_from_invalid_grant_and_never_echo_foreign_detail() {
    let f = fixture(false);
    let tokens = TokenHttp::new();
    let client = client(&f, tokens.clone(), authentication(false)).unwrap();
    for (status, body, authorization) in [
        (
            400,
            json!({"error":"invalid_grant","error_description":"private-provider-detail"}),
            true,
        ),
        (
            400,
            json!({"error":"invalid_client","error_description":"private-provider-detail"}),
            false,
        ),
        (401, json!({"error":"invalid_client"}), false),
        (503, json!({"error":"unavailable"}), false),
    ] {
        let (exchange, _) = f.exchange().await;
        tokens.status.store(status, Ordering::SeqCst);
        *tokens.body.lock().unwrap() = serde_json::to_vec(&body).unwrap();
        let error = client.exchange(exchange, code()).await.err().unwrap();
        assert!(!error.to_string().contains("private-provider-detail"));
        assert!(matches!(
            (authorization, error),
            (true, Error::Unauthorized) | (false, Error::Unavailable)
        ));
    }
}

#[tokio::test]
async fn mismatched_source_and_non_signin_purpose_are_rejected_before_post() {
    let f = fixture(false);
    let tokens = TokenHttp::new();
    let client = client(&f, tokens.clone(), authentication(false)).unwrap();
    let other = fixture(false);
    let (exchange, _) = other.exchange().await;
    assert!(matches!(
        client.exchange(exchange, code()).await,
        Err(Error::Unauthorized)
    ));
    let flow = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
    let browser = Secret::generate().unwrap();
    let session = Secret::generate().unwrap();
    for purpose in [
        OAuthPurpose::Link {
            user: uuid::Uuid::new_v4(),
            session: session.verifier(),
        },
        OAuthPurpose::DeleteProviderAccount {
            user: uuid::Uuid::new_v4(),
            session: session.verifier(),
        },
    ] {
        let intent = OAuthIntent {
            browser: &browser,
            source: "owned-google",
            purpose,
        };
        let start = flow.begin(&intent).await.unwrap();
        let exchange = flow
            .consume(
                &intent,
                &start.state,
                start.proof,
                OAuthCallback {
                    redirect: f.store.connection.redirect(),
                    issuer: Some(f.store.connection.issuer()),
                },
            )
            .await
            .unwrap();
        assert!(matches!(
            client.exchange(exchange, code()).await,
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(tokens.posts(), 0);
}
