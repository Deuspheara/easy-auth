use super::*;
use auth_core::{IssuerAuthorization, IssuerAuthorizationInput, IssuerPkceVerifier, Secret};
use std::sync::Arc;

#[sqlx::test]
async fn configured_offline_profile_cannot_use_existing_online_consent_even_with_enabled_policy(
    pool: PgPool,
) {
    let (store, input) = setup(&pool).await;
    let policy = store
        .configure_issuer_native_refresh_policy(&input)
        .await
        .unwrap();
    store
        .enable_issuer_native_refresh_policy(&policy)
        .await
        .unwrap();
    let current =
        crate::support::signed_in(&store, policy.authority().realm(), "owner@example.test").await;
    let store = Arc::new(store);
    let authorization = IssuerAuthorization::new(policy.authority().clone(), store.clone());
    let browser = Secret::generate().unwrap();
    let pkce = IssuerPkceVerifier::parse(Secret::generate().unwrap().expose().to_owned()).unwrap();
    for scope in ["openid", "openid offline_access", "offline_access"] {
        assert!(matches!(
            authorization
                .prepare(
                    &current,
                    &browser,
                    &IssuerAuthorizationInput {
                        client: policy.client().client(),
                        response_type: "code",
                        redirect_uri: "http://127.0.0.1:41002/cb",
                        scope,
                        state: "owned-state",
                        nonce: "owned-nonce",
                        code_challenge: &pkce.challenge(),
                        code_challenge_method: "S256",
                    }
                )
                .await,
            Err(Error::InvalidInput)
        ));
    }
    for table in [
        "auth_issuer_authorizations",
        "auth_issuer_subjects",
        "auth_issuer_access_tokens",
    ] {
        assert_eq!(
            sqlx::query_scalar::<_, i64>(&format!("SELECT count(*) FROM {table}"))
                .fetch_one(&pool)
                .await
                .unwrap(),
            0
        );
    }
    store
        .check_issuer_native_refresh_policy(&policy)
        .await
        .unwrap();
    // Healthy existing online native client on the same genuine fresh session.
    let online = store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_loopback(
                policy.authority().realm(),
                Uuid::new_v4(),
                &["http://127.0.0.1/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let pending = authorization
        .prepare(
            &current,
            &browser,
            &IssuerAuthorizationInput {
                client: online.client(),
                response_type: "code",
                redirect_uri: "http://127.0.0.1:41002/cb",
                scope: "openid",
                state: "owned-state",
                nonce: "owned-nonce",
                code_challenge: &pkce.challenge(),
                code_challenge_method: "S256",
            },
        )
        .await
        .unwrap();
    authorization
        .approve(
            &current,
            &browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
}
