use super::{
    super::response::Failure,
    tls_fixture::Fixture,
    token_fixture::{Http, Store},
};
use auth_core::*;
use std::sync::Arc;

async fn exchange(f: &Fixture, path: &str) -> (Result<VerifiedOidcIdentity>, Arc<Http>) {
    let store = Store::new(f);
    let http = Http::new(f, path);
    let documents = Arc::new(
        OidcDocuments::new(
            store.connection.clone(),
            &[&f.url("").origin().ascii_serialization()],
            store.clone(),
            http.clone(),
        )
        .unwrap(),
    );
    let flow = OidcCodeExchange::new(
        documents,
        store.clone(),
        OidcVerificationPolicy::new(&[OidcSigningAlgorithm::ES256], &[]).unwrap(),
        OidcClientAuthentication::ClientSecretBasic(
            OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
        ),
        http.clone(),
    );
    let result = flow
        .exchange(
            store.exchange().await,
            OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
        )
        .await;
    (result, http)
}

#[tokio::test]
async fn real_tls_token_post_preserves_credentials_pkce_and_provider_error_classification() {
    let f = Fixture::new().await;
    let (result, http) = exchange(&f, "/invalid-grant").await;
    assert!(
        matches!(result, Err(Error::Unauthorized)),
        "working TLS/provider denial control"
    );
    assert!(http.failure.lock().unwrap().is_none());
    let (result, http) = exchange(&f, "/invalid-client").await;
    assert!(matches!(result, Err(Error::Unavailable)));
    assert!(
        http.failure.lock().unwrap().is_none(),
        "provider configuration error, not a broken fixture"
    );
    {
        let captured = f.facts.requests.lock().unwrap();
        assert_eq!(captured.len(), 2);
        for (sni, headers) in captured.iter() {
            assert_eq!(sni, "fixture.invalid");
            assert!(headers.starts_with("POST /invalid-"));
            let headers = headers.to_ascii_lowercase();
            assert!(headers.contains("content-type: application/x-www-form-urlencoded\r\n"));
            assert!(headers.contains("authorization: basic "));
            assert!(headers.contains("cache-control: no-store\r\n"));
            assert!(!headers.contains("cookie:"));
            assert!(headers.contains(&format!("host: fixture.invalid:{}", f.address.port())));
        }
        let bodies = f.facts.bodies.lock().unwrap();
        for body in bodies.iter() {
            let form: Vec<_> = url::form_urlencoded::parse(body).collect();
            assert!(
                form.iter()
                    .any(|(key, value)| key == "code" && !value.is_empty())
            );
            assert!(
                form.iter()
                    .any(|(key, value)| key == "code_verifier" && value.len() == 43)
            );
            assert!(form.iter().any(
                |(key, value)| key == "redirect_uri" && value == "https://app.example/callback"
            ));
            assert!(!form.iter().any(|(key, _)| key == "client_secret"));
        }
    }
    f.close().await;
}

#[tokio::test]
async fn real_tls_token_post_rejects_redirects_and_bad_envelopes_without_retrying_credentials() {
    let f = Fixture::new().await;
    for (path, expected) in [
        ("/redirect", Failure::Status),
        ("/declared", Failure::Size),
        ("/chunked", Failure::Size),
        ("/encoding", Failure::Encoding),
        ("/headers", Failure::Headers),
        ("/html", Failure::ContentType),
        ("/duplicate-type", Failure::ContentType),
        ("/stall", Failure::Timeout),
    ] {
        let (result, http) = exchange(&f, path).await;
        assert!(matches!(result, Err(Error::Unavailable)));
        assert_eq!(
            *http.failure.lock().unwrap(),
            Some(expected),
            "network or fixture failure must not count as {path} policy rejection"
        );
    }
    assert_eq!(f.facts.requests.lock().unwrap().len(), 8);
    assert!(
        !f.facts
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(_, headers)| headers.contains("/forbidden"))
    );
    f.close().await;
}
