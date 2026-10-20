use super::super::setup::Fixture;
use super::setup::{Http, client};
use crate::{
    Error, OAuthIntent, OAuthPurpose, OAuthTransactions, OidcClientAuthentication,
    OidcSigningAlgorithm, Secret,
};
use serde_json::json;
use uuid::Uuid;

#[tokio::test]
async fn reauthentication_has_fixed_parameters_and_preserves_original_protocol_binding() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    f.http.metadata.lock().unwrap()["token_endpoint_auth_methods_supported"] = json!(["none"]);
    let client = client(&f, Http::new(), OidcClientAuthentication::Public);
    let flow = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
    let browser = Secret::generate().unwrap();
    let start = flow
        .begin(&OAuthIntent {
            browser: &browser,
            source: "owned-reauth",
            purpose: OAuthPurpose::DeleteProviderAccount {
                user: Uuid::new_v4(),
                session: Secret::generate().unwrap().verifier(),
            },
        })
        .await
        .unwrap();
    let normal = client
        .authorization_url(&start, &["profile"])
        .await
        .unwrap();
    let fresh = client
        .reauthentication_url(&start, &["profile"])
        .await
        .unwrap();
    let normal = url::Url::parse(normal.expose()).unwrap();
    let fresh = url::Url::parse(fresh.expose()).unwrap();
    let base: Vec<_> = normal.query_pairs().into_owned().collect();
    let mut expected = base.clone();
    expected.extend([
        ("max_age".into(), "0".into()),
        ("prompt".into(), "login".into()),
    ]);
    assert!(
        fresh.query_pairs().into_owned().collect::<Vec<_>>() == expected,
        "reauthentication must preserve the exact original state/nonce/PKCE binding"
    );
    assert!(
        !base
            .iter()
            .any(|(key, _)| key == "max_age" || key == "prompt")
    );
    let invalid = flow
        .begin(&OAuthIntent {
            browser: &browser,
            source: "owned-reauth",
            purpose: OAuthPurpose::DeleteProviderAccount {
                user: Uuid::nil(),
                session: Secret::generate().unwrap().verifier(),
            },
        })
        .await;
    assert!(matches!(invalid, Err(Error::InvalidInput)));
}

#[tokio::test]
async fn provider_metadata_cannot_override_or_duplicate_reauthentication_policy() {
    for suffix in [
        "prompt=none",
        "max_age=9999",
        "MAX_AGE=9999",
        "p%72ompt=none",
    ] {
        let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
        {
            let mut metadata = f.http.metadata.lock().unwrap();
            metadata["token_endpoint_auth_methods_supported"] = json!(["none"]);
            metadata["authorization_endpoint"] =
                json!(format!("https://issuer.example/authorize?{suffix}"));
        }
        let http = Http::new();
        let client = client(&f, http.clone(), OidcClientAuthentication::Public);
        let flow = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
        let browser = Secret::generate().unwrap();
        let start = flow
            .begin(&OAuthIntent {
                browser: &browser,
                source: "owned-reauth",
                purpose: OAuthPurpose::SignIn,
            })
            .await
            .unwrap();
        assert!(matches!(
            client.reauthentication_url(&start, &[]).await,
            Err(Error::Unavailable)
        ));
        assert!(matches!(
            client.authorization_url(&start, &[]).await,
            Err(Error::Unavailable)
        ));
        assert_eq!(http.posts(), 0);
    }
}
