use super::setup::{flow, input};
use crate::support::realm;
use auth_core::*;
use sqlx::PgPool;
use std::sync::Arc;

#[sqlx::test(migrations = "./migrations")]
async fn full_native_definition_checks_profile_and_operator_disable_before_accepting_returns(
    pool: PgPool,
) {
    let (store, realm) = realm(pool.clone()).await;
    let store = Arc::new(store);
    let definition = input(realm);
    let policy = OidcIdentityPolicy::new(
        definition,
        &["https://issuer.example"],
        OidcDisplayNameClaim::Subject,
    )
    .unwrap()
    .with_jit(OidcJitPolicy::Allow);
    let policy = store.configure_oidc_identity_policy(&policy).await.unwrap();
    let c = policy.configuration();
    let url = url::Url::parse(c.redirect()).unwrap();
    let exact = OAuthConnection::with_redirect(
        c.realm(),
        c.connection(),
        c.client(),
        c.issuer(),
        c.provider_client(),
        OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), url.path()).unwrap(),
        c.defense(),
    )
    .unwrap();
    let exact = OidcIdentityPolicy::new(exact, &[c.issuer()], policy.display_name_claim())
        .unwrap()
        .with_jit(policy.jit())
        .with_persisted_revision(c.revision())
        .unwrap();
    assert!(matches!(
        store.load_or_initialize_oidc_identity_policy(&exact).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store.check_oidc_connection(exact.configuration()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        store
            .load_or_initialize_oidc_identity_policy(&policy)
            .await
            .unwrap(),
        policy
    );
    let original = flow(c, store.clone(), 49154);
    let browser = Secret::generate().unwrap();
    let intent = OAuthIntent {
        browser: &browser,
        source: "desktop-definition",
        purpose: OAuthPurpose::SignIn,
    };
    let pending = original.begin(&intent).await.unwrap();
    store
        .disable_oauth_connection(c.realm(), c.connection(), c.client())
        .await
        .unwrap();
    assert!(matches!(
        original
            .cancel(&intent, &pending.state, &pending.proof)
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        store.load_or_initialize_oidc_identity_policy(&policy).await,
        Err(Error::Unauthorized)
    ));
    let disabled = store.configure_oidc_identity_policy(&policy).await.unwrap();
    let current = flow(disabled.configuration(), store.clone(), 49155);
    assert!(matches!(
        current.begin(&intent).await,
        Err(Error::Unauthorized)
    ));
    store
        .enable_oauth_connection(disabled.configuration())
        .await
        .unwrap();
    let valid = current.begin(&intent).await.unwrap();
    current
        .consume(
            &intent,
            &valid.state,
            valid.proof,
            OAuthCallback {
                redirect: current.redirect(),
                issuer: Some(c.issuer()),
            },
        )
        .await
        .unwrap();
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_oauth_transactions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
}
