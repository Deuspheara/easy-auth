use super::super::setup::{Fixture, NOW_US, TokenHttp};
use super::setup::*;
use crate::*;
use serde_json::{Value, json};
use std::sync::atomic::Ordering;
use uuid::Uuid;

const NOW: u64 = (NOW_US / 1_000_000) as u64;

async fn exchange_for(f: &Fixture, purpose: OAuthPurpose) -> (OAuthExchange, Value) {
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "owned-session-age",
        purpose,
    };
    let flow = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
    let start = flow.begin(&intent).await.unwrap();
    let claims = json!({"iss":f.store.connection.issuer(),"aud":f.store.connection.provider_client(),"sub":"subject","nonce":start.proof.nonce().expose(),"iat":NOW,"exp":NOW+300,"auth_time":NOW});
    let context = flow
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
    (context, claims)
}

#[tokio::test]
async fn session_age_profile_requests_only_fixed_claim_without_changing_default_or_original_proofs()
{
    for desktop in [false, true] {
        let f = fixture(desktop);
        let tokens = TokenHttp::new();
        let base = client(&f, tokens.clone(), authentication(false)).unwrap();
        let selected = client(&f, tokens.clone(), authentication(false))
            .unwrap()
            .with_session_age_claims();
        assert_eq!(selected.configuration(), base.configuration());
        let browser = Secret::generate().unwrap();
        let flow = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
        let start = flow
            .begin(&OAuthIntent {
                browser: &browser,
                source: "owned-session-age",
                purpose: OAuthPurpose::SignIn,
            })
            .await
            .unwrap();
        let basic = base.authorization_url(&start).await.unwrap();
        let destination = selected.authorization_url(&start).await.unwrap();
        let basic = url::Url::parse(basic.expose()).unwrap();
        let selected = url::Url::parse(destination.expose()).unwrap();
        let base_pairs: Vec<_> = basic.query_pairs().collect();
        let pairs: Vec<_> = selected.query_pairs().collect();
        assert!(!base_pairs.iter().any(|(name, _)| name == "claims"));
        assert!(
            pairs
                .iter()
                .filter(|(name, _)| name != "claims")
                .cloned()
                .collect::<Vec<_>>()
                == base_pairs,
            "session-age request retains original protocol values without formatting private fields"
        );
        let claims: Vec<_> = pairs.iter().filter(|(name, _)| name == "claims").collect();
        assert_eq!(claims.len(), 1);
        assert_eq!(
            serde_json::from_str::<Value>(&claims[0].1).unwrap(),
            json!({"id_token":{"auth_time":{"essential":true}}})
        );
        assert!(!pairs.iter().any(|(name, _)| matches!(
            name.as_ref(),
            "prompt" | "max_age" | "code_verifier" | "client_secret"
        )));
        assert_eq!(
            format!("{destination:?}"),
            "OidcAuthorizationUrl([REDACTED])"
        );
        assert_eq!(tokens.posts(), 0);
    }
}

#[tokio::test]
async fn session_age_profile_refuses_decoded_case_folded_claims_collisions_before_post() {
    for parameter in ["claims", "CLAIMS", "%63laims", "claims=one&claims"] {
        let f = fixture(false);
        f.http.metadata.lock().unwrap()["authorization_endpoint"] =
            format!("https://accounts.google.com/o/oauth2/v2/auth?{parameter}=foreign").into();
        let tokens = TokenHttp::new();
        let selected = client(&f, tokens.clone(), authentication(false))
            .unwrap()
            .with_session_age_claims();
        let browser = Secret::generate().unwrap();
        let flow = OAuthTransactions::new(f.store.connection.clone(), f.store.clone());
        let start = flow
            .begin(&OAuthIntent {
                browser: &browser,
                source: "owned-session-age",
                purpose: OAuthPurpose::SignIn,
            })
            .await
            .unwrap();
        assert!(matches!(
            selected.authorization_url(&start).await,
            Err(Error::Unavailable)
        ));
        assert!(f.gets() > 0, "actual provider metadata path observed");
        assert_eq!(tokens.posts(), 0);
    }
}

#[tokio::test]
async fn session_age_missing_signed_capability_is_distinct_from_malformed_or_invalid_authentication_time()
 {
    let f = fixture(false);
    let tokens = TokenHttp::new();
    let selected = client(&f, tokens.clone(), authentication(false))
        .unwrap()
        .with_session_age_claims();
    let (context, claims) = f.exchange().await;
    tokens.success(&f, &claims);
    assert!(matches!(
        selected.exchange(context, code()).await,
        Err(Error::Unavailable)
    ));
    for value in [Value::Null, json!("recent"), json!(true), json!(NOW + 3600)] {
        let (context, mut claims) = f.exchange().await;
        claims["auth_time"] = value;
        tokens.success(&f, &claims);
        assert!(matches!(
            selected.exchange(context, code()).await,
            Err(Error::Unauthorized)
        ));
    }
    let (context, mut claims) = f.exchange().await;
    claims["auth_time"] = json!(NOW);
    tokens.success(&f, &claims);
    assert_eq!(
        selected
            .exchange(context, code())
            .await
            .unwrap()
            .authenticated_at(),
        Some(NOW)
    );
    assert_eq!(
        tokens.posts(),
        6,
        "every claim result follows an actual signed token response"
    );
}

#[tokio::test]
async fn session_age_signin_and_account_deletion_methods_reject_cross_purpose_and_linking_before_post()
 {
    let f = fixture(false);
    let tokens = TokenHttp::new();
    let selected = client(&f, tokens.clone(), authentication(false))
        .unwrap()
        .with_session_age_claims();
    let session = Secret::generate().unwrap();
    for deletion in [false, true] {
        for dimension in 0..3 {
            let purpose = match dimension {
                0 => OAuthPurpose::SignIn,
                1 => OAuthPurpose::DeleteProviderAccount {
                    user: Uuid::new_v4(),
                    session: session.verifier(),
                },
                _ => OAuthPurpose::Link {
                    user: Uuid::new_v4(),
                    session: session.verifier(),
                },
            };
            let (context, claims) = exchange_for(&f, purpose).await;
            tokens.success(&f, &claims);
            let before = tokens.posts();
            let result = if deletion {
                selected.exchange_account_deletion(context, code()).await
            } else {
                selected.exchange(context, code()).await
            };
            if dimension == usize::from(deletion) {
                assert!(result.is_ok());
                assert_eq!(tokens.posts(), before + 1);
            } else {
                assert!(matches!(result, Err(Error::Unauthorized)));
                assert_eq!(tokens.posts(), before);
            }
        }
    }
    assert_eq!(tokens.posts(), 2);
}

#[tokio::test]
async fn session_age_old_signed_authentication_time_stays_old_in_both_proof_purposes() {
    let f = fixture(true);
    let tokens = TokenHttp::new();
    let selected = client(&f, tokens.clone(), authentication(true))
        .unwrap()
        .with_session_age_claims();
    let session = Secret::generate().unwrap();
    for deletion in [false, true] {
        let purpose = if deletion {
            OAuthPurpose::DeleteProviderAccount {
                user: Uuid::new_v4(),
                session: session.verifier(),
            }
        } else {
            OAuthPurpose::SignIn
        };
        let (context, mut claims) = exchange_for(&f, purpose).await;
        claims["auth_time"] = json!(NOW - 3600);
        tokens.success(&f, &claims);
        let identity = if deletion {
            selected.exchange_account_deletion(context, code()).await
        } else {
            selected.exchange(context, code()).await
        }
        .unwrap();
        assert_eq!(identity.authenticated_at(), Some(NOW - 3600));
        assert_eq!(
            identity.issued_at(),
            NOW,
            "new token issuance cannot rewrite signed authentication"
        );
    }
    assert_eq!(tokens.posts(), 2);
}

#[tokio::test]
async fn session_age_foreign_source_and_transport_failure_do_not_become_valid_profile_proof() {
    let f = fixture(false);
    let tokens = TokenHttp::new();
    let selected = client(&f, tokens.clone(), authentication(false))
        .unwrap()
        .with_session_age_claims();
    let foreign = fixture(false);
    let (context, _) = foreign.exchange().await;
    assert!(matches!(
        selected.exchange(context, code()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(tokens.posts(), 0);
    tokens.fail.store(true, Ordering::SeqCst);
    let (context, claims) = exchange_for(&f, OAuthPurpose::SignIn).await;
    tokens.success(&f, &claims);
    assert!(matches!(
        selected.exchange(context, code()).await,
        Err(Error::Unavailable)
    ));
    tokens.fail.store(false, Ordering::SeqCst);
    let (context, claims) = exchange_for(&f, OAuthPurpose::SignIn).await;
    tokens.success(&f, &claims);
    assert_eq!(
        selected
            .exchange(context, code())
            .await
            .unwrap()
            .authenticated_at(),
        Some(NOW)
    );
    assert_eq!(tokens.posts(), 2);
}
