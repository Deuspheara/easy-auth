use super::super::setup::Fixture;
use super::setup::{counts, snapshot};
use crate::support::realm;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;

fn policy(realm: Uuid) -> OidcIdentityPolicy {
    let c = OAuthConnection::with_redirect(
        realm,
        Uuid::new_v4(),
        Uuid::new_v4(),
        "https://issuer.example",
        "registered-desktop-client",
        OAuthRedirect::desktop_loopback("127.0.0.1:49153".parse().unwrap(), "/callback").unwrap(),
        OAuthMixupDefense::RequireIssuer,
    )
    .unwrap();
    OidcIdentityPolicy::new(
        c,
        &["https://issuer.example"],
        OidcDisplayNameClaim::Subject,
    )
    .unwrap()
    .with_jit(OidcJitPolicy::Allow)
}

#[sqlx::test(migrations = "./migrations")]
async fn native_policy_restart_retains_signed_session_but_reconfiguration_revokes_old_source(
    pool: PgPool,
) {
    let (store, realm) = realm(pool.clone()).await;
    let mut f = Fixture::configured(pool, Arc::new(store), policy(realm)).await;
    let original = f.policy.clone();
    let (user, session) = f
        .sign_in
        .finish(f.mapped("native-owner", json!({})).await)
        .await
        .unwrap();
    let before = snapshot(&f.pool).await;
    f.load_at_startup().await.unwrap();
    assert_eq!(f.policy, original);
    assert!(
        before == snapshot(&f.pool).await,
        "native startup must not rewrite authority or audit"
    );
    assert_eq!(
        f.store
            .authenticate(realm, session.verifier())
            .await
            .unwrap()
            .id,
        user.id
    );
    let old = f.mapped("native-owner", json!({})).await;
    let before = f.facts().await;
    f.reconfigure(OidcJitPolicy::Allow).await;
    assert_eq!(
        f.policy.configuration().redirect(),
        original.configuration().redirect()
    );
    assert_ne!(
        f.policy.configuration().revision(),
        original.configuration().revision()
    );
    assert!(matches!(
        f.sign_in.finish(old).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.facts().await,
        before,
        "stale signed native source must not mutate authority"
    );
    assert!(matches!(
        f.store.authenticate(realm, session.verifier()).await,
        Err(Error::Unauthorized)
    ));
    let (same, _) = f
        .sign_in
        .finish(f.mapped("native-owner", json!({})).await)
        .await
        .unwrap();
    assert_eq!(
        same.id, user.id,
        "current signed native source resolves the original identity"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn native_callback_is_globally_unique_and_first_startup_is_stable(pool: PgPool) {
    let (store, realm) = realm(pool.clone()).await;
    let input = policy(realm);
    let first = store
        .load_or_initialize_oidc_identity_policy(&input)
        .await
        .unwrap();
    assert_ne!(
        first.configuration().revision(),
        input.configuration().revision()
    );
    assert_eq!(counts(&pool).await, (1, 1, 0, 0, 0));
    let before = snapshot(&pool).await;
    assert_eq!(
        store
            .load_or_initialize_oidc_identity_policy(&input)
            .await
            .unwrap(),
        first
    );
    let other = Uuid::new_v4();
    store.ensure_realm(other).await.unwrap();
    assert!(
        matches!(
            store.configure_oidc_identity_policy(&policy(other)).await,
            Err(Error::Unavailable)
        ),
        "a duplicate native callback cannot silently select another realm/client"
    );
    assert!(
        before == snapshot(&pool).await,
        "a conflicting callback must roll back without touching the original source"
    );
}
