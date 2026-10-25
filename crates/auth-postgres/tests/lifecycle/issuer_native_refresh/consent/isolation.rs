use super::*;
use auth_core::{
    IssuerAuthority, IssuerAuthorizationRepository, IssuerClientRegistration,
    IssuerNativeAuthorizationRequest,
};

#[sqlx::test]
async fn genuine_same_client_id_in_another_realm_cannot_select_or_approve_native_consent(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone()).await;
    let a = f.prepare().await;
    let (store, realm) = crate::support::realm(pool.clone()).await;
    let client = store
        .configure_issuer_client(
            &IssuerClientRegistration::public_native_refresh_loopback(
                realm,
                f.policy.client().client(),
                &["http://127.0.0.1/cb"],
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let authority = IssuerAuthority::new(realm, f.policy.authority().issuer()).unwrap();
    let policy = store
        .configure_issuer_native_refresh_policy(
            &IssuerNativeRefreshPolicy::new(authority.clone(), client, 86400, 3600).unwrap(),
        )
        .await
        .unwrap();
    store
        .enable_issuer_native_refresh_policy(&policy)
        .await
        .unwrap();
    let current = crate::support::signed_in(&store, realm, "owner@example.test").await;
    let store = Arc::new(store);
    let service = IssuerNativeAuthorization::new(authority, store.clone());
    let browser = Secret::generate().unwrap();
    let b = service
        .prepare(
            &current,
            &browser,
            &IssuerNativeAuthorizationInput {
                authorization: IssuerAuthorizationInput {
                    client: policy.client().client(),
                    response_type: "code",
                    redirect_uri: "http://127.0.0.1:41002/cb",
                    scope: "openid offline_access",
                    state: "owned-state",
                    nonce: "owned-nonce",
                    code_challenge: &f.pkce.challenge(),
                    code_challenge_method: "S256",
                },
                prompt: "consent",
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        service
            .approve(&current, &browser, a.handle(), a.authorization())
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.service
            .preview(&f.current, &f.browser, b.handle(), b.authorization())
            .await,
        Err(Error::Unauthorized)
    ));
    f.service
        .approve(&f.current, &f.browser, a.handle(), a.authorization())
        .await
        .unwrap();
    service
        .cancel(&current, &browser, b.handle(), b.authorization())
        .await
        .unwrap();
    assert_eq!(f.facts().await, (1, 1, 1, 0, 1));
    assert_eq!(
        sqlx::query_scalar::<_, i64>(
            "SELECT count(*) FROM auth_issuer_native_consents WHERE realm_id=$1"
        )
        .bind(realm)
        .fetch_one(&pool)
        .await
        .unwrap(),
        0
    );
    store.authenticate(realm, current.verifier()).await.unwrap();
}

#[sqlx::test]
async fn client_replacement_invalidates_pending_native_consent_without_restoring_old_policy(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let pending = f.prepare().await;
    let current = f
        .store
        .configure_issuer_client(f.policy.client())
        .await
        .unwrap();
    assert_ne!(current.revision(), f.policy.client().revision());
    assert!(
        f.service
            .preview(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await
            .is_err()
    );
    assert!(
        f.service
            .approve(
                &f.current,
                &f.browser,
                pending.handle(),
                pending.authorization()
            )
            .await
            .is_err()
    );
    assert!(
        f.store
            .enable_issuer_native_refresh_policy(&f.policy)
            .await
            .is_err()
    );
    assert!(
        f.prepare_with("openid offline_access", "consent")
            .await
            .is_err()
    );
    assert_eq!(f.facts().await, (1, 1, 0, 0, 0));
}

#[sqlx::test]
async fn explicit_native_request_component_cannot_be_saved_by_default_online_repository(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let request = IssuerNativeAuthorizationRequest::new(
        f.policy.clone(),
        &IssuerNativeAuthorizationInput {
            authorization: IssuerAuthorizationInput {
                client: f.policy.client().client(),
                response_type: "code",
                redirect_uri: "http://127.0.0.1:41002/cb",
                scope: "openid offline_access",
                state: "owned-state",
                nonce: "owned-nonce",
                code_challenge: &f.pkce.challenge(),
                code_challenge_method: "S256",
            },
            prompt: "consent",
        },
    )
    .unwrap();
    let handle = Secret::generate().unwrap();
    assert!(matches!(
        f.store
            .save_issuer_authorization(
                request.code(),
                f.current.verifier(),
                f.browser.verifier(),
                handle.verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    let pending = f.prepare().await;
    f.service
        .approve(
            &f.current,
            &f.browser,
            pending.handle(),
            pending.authorization(),
        )
        .await
        .unwrap();
}
