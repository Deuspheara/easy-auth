use super::super::setup::Fixture;
use super::setup::{Http, client};
use crate::{
    Error, OidcAuthorizationCode, OidcClientAuthentication, OidcClientSecret, OidcSigningAlgorithm,
    Secret,
};
use serde_json::json;
use std::sync::atomic::Ordering;

#[tokio::test]
async fn provider_code_denial_is_distinct_from_malformed_responses_and_infrastructure_failure() {
    for (status, body, denial) in [
        (400, json!({"error":"invalid_grant"}), true),
        (401, json!({"error":"invalid_client"}), false),
        (400, json!({"error":"invalid_request"}), false),
        (503, json!({"error":"temporarily_unavailable"}), false),
        (
            200,
            json!({"access_token":"unused","token_type":"Bearer"}),
            false,
        ),
        (
            200,
            json!({"id_token":"x.y.z","token_type":"Bearer"}),
            false,
        ),
        (
            200,
            json!({"id_token":"x.y.z","access_token":"unused","token_type":"other"}),
            false,
        ),
    ] {
        let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
        let http = Http::new();
        http.status.store(status, Ordering::SeqCst);
        *http.body.lock().unwrap() = serde_json::to_vec(&body).unwrap();
        let client = client(
            &f,
            http.clone(),
            OidcClientAuthentication::ClientSecretBasic(
                OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
            ),
        );
        let (exchange, _) = f.exchange().await;
        let result = client
            .exchange(
                exchange,
                OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned())
                    .unwrap(),
            )
            .await;
        if denial {
            assert!(matches!(result, Err(Error::Unauthorized)));
        } else {
            assert!(matches!(result, Err(Error::Unavailable)));
        }
        assert_eq!(
            http.posts(),
            1,
            "provider failures must not retry a consumed code"
        );
    }
}

#[tokio::test]
async fn duplicate_id_token_and_unsupported_response_envelopes_never_verify() {
    for mode in ["duplicate", "mime", "encoding", "oversize"] {
        let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
        let http = Http::new();
        let (exchange, claims) = f.exchange().await;
        http.success(&f, &claims);
        match mode {
            "duplicate" => {
                let mut response: serde_json::Value =
                    serde_json::from_slice(&http.body.lock().unwrap()).unwrap();
                let token = response
                    .as_object_mut()
                    .unwrap()
                    .remove("id_token")
                    .unwrap();
                let rest = serde_json::to_string(&response).unwrap();
                *http.body.lock().unwrap() =
                    format!("{{\"id_token\":{token},\"id_token\":{token},{}", &rest[1..])
                        .into_bytes();
            }
            "mime" => {
                *http.content_type.lock().unwrap() = "text/html".into();
            }
            "encoding" => {
                *http.encoding.lock().unwrap() = Some("gzip".into());
            }
            _ => {
                *http.body.lock().unwrap() = vec![b' '; 65537];
            }
        }
        let client = client(
            &f,
            http.clone(),
            OidcClientAuthentication::ClientSecretBasic(
                OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
            ),
        );
        assert!(matches!(
            client
                .exchange(
                    exchange,
                    OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned())
                        .unwrap()
                )
                .await,
            Err(Error::Unavailable)
        ));
        assert_eq!(http.posts(), 1);
    }
}

#[tokio::test]
async fn a_previously_valid_id_token_cannot_authenticate_a_new_claimed_transaction() {
    let f = Fixture::new(OidcSigningAlgorithm::ES256, &[]);
    let http = Http::new();
    let client = client(
        &f,
        http.clone(),
        OidcClientAuthentication::ClientSecretBasic(
            OidcClientSecret::parse(Secret::generate().unwrap().expose().to_owned()).unwrap(),
        ),
    );
    let (first, claims) = f.exchange().await;
    http.success(&f, &claims);
    assert_eq!(
        client
            .exchange(
                first,
                OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned())
                    .unwrap()
            )
            .await
            .unwrap()
            .subject(),
        "subject"
    );
    let (second, _) = f.exchange().await;
    assert!(
        matches!(
            client
                .exchange(
                    second,
                    OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned())
                        .unwrap()
                )
                .await,
            Err(Error::Unauthorized)
        ),
        "fresh state must not accept a captured token with another nonce"
    );
    let (control, claims) = f.exchange().await;
    http.success(&f, &claims);
    assert_eq!(
        client
            .exchange(
                control,
                OidcAuthorizationCode::parse(Secret::generate().unwrap().expose().to_owned())
                    .unwrap()
            )
            .await
            .unwrap()
            .subject(),
        "subject"
    );
    assert_eq!(http.posts(), 3);
}
