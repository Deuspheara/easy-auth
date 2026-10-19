use super::super::setup::Fixture;
use super::setup::{Http, client};
use crate::{
    Error, OAuthIntent, OAuthPurpose, OAuthTransactions, OidcAuthorizationCode,
    OidcClientAuthentication, OidcClientSecret, OidcSigningAlgorithm, Secret,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::json;
use zeroize::Zeroizing;

#[tokio::test]
async fn every_registered_method_sends_exact_code_redirect_and_original_pkce_once() {
    for method in ["none", "client_secret_basic", "client_secret_post"] {
        let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
        f.http.metadata.lock().unwrap()["token_endpoint_auth_methods_supported"] = json!([method]);
        let secret = Zeroizing::new(format!(
            "prefix:+ /{}é",
            Secret::generate().unwrap().expose()
        ));
        let auth = match method {
            "none" => OidcClientAuthentication::Public,
            "client_secret_basic" => OidcClientAuthentication::ClientSecretBasic(
                OidcClientSecret::parse(secret.to_string()).unwrap(),
            ),
            _ => OidcClientAuthentication::ClientSecretPost(
                OidcClientSecret::parse(secret.to_string()).unwrap(),
            ),
        };
        let http = Http::new();
        let client = client(&f, http.clone(), auth);
        let (exchange, claims) = f.exchange().await;
        let pkce = Zeroizing::new(exchange.proof().pkce_verifier().expose().to_owned());
        http.success(&f, &claims);
        let code = Zeroizing::new(Secret::generate().unwrap().expose().to_owned());
        let result = client
            .exchange(
                exchange,
                OidcAuthorizationCode::parse(code.to_string()).unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(result.subject(), "subject");
        assert_eq!(http.posts(), 1);
        let seen = http.seen.lock().unwrap();
        let seen = &seen[0];
        assert_eq!(seen.url, "https://issuer.example/token");
        let pairs: Vec<_> = url::form_urlencoded::parse(seen.form.as_bytes()).collect();
        let value = |name: &str| {
            pairs
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.as_ref())
        };
        assert!(
            value("code") == Some(code.as_str()),
            "code must remain exact without diagnostic output"
        );
        assert!(
            value("code_verifier") == Some(pkce.as_str()),
            "PKCE verifier must be the original private proof"
        );
        assert!(value("redirect_uri") == Some(f.store.connection.redirect()));
        assert!(value("grant_type") == Some("authorization_code"));
        assert!(value("state").is_none() && value("nonce").is_none());
        if method == "client_secret_basic" {
            assert!(value("client_id").is_none() && value("client_secret").is_none());
            let header = seen
                .authorization
                .as_deref()
                .expect("Basic header required");
            let decoded = Zeroizing::new(
                STANDARD
                    .decode(header.strip_prefix("Basic ").unwrap())
                    .unwrap(),
            );
            let decoded = std::str::from_utf8(&decoded).unwrap();
            assert_eq!(
                decoded.matches(':').count(),
                1,
                "form encoding must protect colon delimiters"
            );
            let (user, password) = decoded.split_once(':').unwrap();
            assert_eq!(user, "client");
            assert!(
                password.contains("%3A")
                    && password.contains("%2B")
                    && password.contains("%2F")
                    && password.contains("%C3%A9")
            );
            let encoded = Zeroizing::new(format!("p={password}"));
            let decoded = url::form_urlencoded::parse(encoded.as_bytes())
                .next()
                .unwrap()
                .1;
            assert!(
                decoded.as_ref() == secret.as_str(),
                "Basic decoding must recover the exact configured credential"
            );
        } else {
            assert!(seen.authorization.is_none());
            assert!(value("client_id") == Some("client"));
            assert!(if method == "none" {
                value("client_secret").is_none()
            } else {
                value("client_secret") == Some(secret.as_str())
            });
        }
    }
}

#[tokio::test]
async fn authorization_url_contains_only_bound_protocol_values_and_s256() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let client = client(
        &f,
        Http::new(),
        OidcClientAuthentication::ClientSecretBasic(
            OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
        ),
    );
    let flow = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
    let browser = Secret::generate().unwrap();
    let start = flow
        .begin(&OAuthIntent {
            browser: &browser,
            source: "authorize-fixture",
            purpose: OAuthPurpose::SignIn,
        })
        .await
        .unwrap();
    let authorization = client
        .authorization_url(&start, &["profile", "openid"])
        .await
        .unwrap();
    assert_eq!(
        format!("{authorization:?}"),
        "OidcAuthorizationUrl([REDACTED])"
    );
    let url = url::Url::parse(authorization.expose()).unwrap();
    let pairs: Vec<_> = url.query_pairs().collect();
    let value = |name: &str| {
        pairs
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_ref())
    };
    assert!(value("state") == Some(start.state.expose()));
    assert!(value("nonce") == Some(start.proof.nonce().expose()));
    assert!(value("code_challenge") == Some(start.proof.code_challenge().as_str()));
    assert_eq!(value("code_challenge_method"), Some("S256"));
    assert_eq!(value("response_type"), Some("code"));
    assert_eq!(value("scope"), Some("openid profile"));
    assert!(value("code_verifier").is_none());
    assert!(matches!(
        client.authorization_url(&start, &["bad scope"]).await,
        Err(Error::InvalidInput)
    ));
}

#[tokio::test]
async fn missing_s256_or_mismatched_registered_method_never_posts_or_downgrades() {
    for mode in [
        "missing-s256",
        "wrong-method",
        "token-query",
        "authorization-query",
    ] {
        let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
        let http = Http::new();
        match mode {
            "missing-s256" => {
                f.http.metadata.lock().unwrap()["code_challenge_methods_supported"] =
                    json!(["plain"]);
            }
            "wrong-method" => {
                f.http.metadata.lock().unwrap()["token_endpoint_auth_methods_supported"] =
                    json!(["none"]);
            }
            "token-query" => {
                f.http.metadata.lock().unwrap()["token_endpoint"] =
                    json!("https://issuer.example/token?code_verifier=other");
            }
            _ => {
                f.http.metadata.lock().unwrap()["authorization_endpoint"] =
                    json!("https://issuer.example/authorize?client_id=other");
            }
        }
        let client = client(
            &f,
            http.clone(),
            OidcClientAuthentication::ClientSecretBasic(
                OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
            ),
        );
        if mode == "authorization-query" {
            let flow = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
            let browser = Secret::generate().unwrap();
            let start = flow
                .begin(&OAuthIntent {
                    browser: &browser,
                    source: "query-fixture",
                    purpose: OAuthPurpose::SignIn,
                })
                .await
                .unwrap();
            assert!(matches!(
                client.authorization_url(&start, &[]).await,
                Err(Error::Unavailable)
            ));
        } else {
            let (exchange, _) = f.exchange().await;
            assert!(matches!(
                client
                    .exchange(
                        exchange,
                        OidcAuthorizationCode::parse(
                            Secret::generate().unwrap().expose().to_owned()
                        )
                        .unwrap()
                    )
                    .await,
                Err(Error::Unavailable)
            ));
        }
        assert_eq!(http.posts(), 0);
    }
}
