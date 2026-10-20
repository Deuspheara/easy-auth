use super::setup::{Fixture, wait_for_lock};
use crate::support::challenge;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn old_provider_authentication_stays_old_and_new_proof_does_not_rewrite_earlier_sessions(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let now = f.now_seconds().await;
    let (_, old) = f
        .sign_in
        .finish(f.mapped("subject", json!({"auth_time":now-360})).await)
        .await
        .unwrap();
    assert!(matches!(
        f.store.revoke_all_sessions(f.realm(), old.verifier()).await,
        Err(Error::Unauthorized)
    ));
    let (_, fresh) = f
        .sign_in
        .finish(f.mapped("subject", json!({"auth_time":now})).await)
        .await
        .unwrap();
    let page = f
        .store
        .list_sessions(f.realm(), fresh.verifier(), None)
        .await
        .unwrap();
    assert!(
        page.sessions
            .iter()
            .any(|s| s.authenticated_at_ms == Some((now - 360) * 1000))
    );
    assert!(
        page.sessions
            .iter()
            .any(|s| s.authenticated_at_ms == Some(now * 1000))
    );
    assert!(matches!(
        f.store.revoke_all_sessions(f.realm(), old.verifier()).await,
        Err(Error::Unauthorized)
    ));
    f.store
        .revoke_all_sessions(f.realm(), fresh.verifier())
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn verified_contact_does_not_enable_mailbox_password_or_deletion_fallback_for_provider_policy(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let now = f.now_seconds().await;
    let (user, current) = f
        .sign_in
        .finish(f.mapped("subject", json!({"auth_time":now})).await)
        .await
        .unwrap();
    let (proof, browser) = challenge(&f.store, f.realm(), "contact@example.test").await;
    // Owned pre-issued mailbox proof + privileged verified-contact fixture. This
    // is not a public provider contact-attachment or policy-transition endpoint.
    sqlx::query("UPDATE auth_users SET email='contact@example.test',email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2").bind(f.realm()).bind(user.id).execute(&f.pool).await.unwrap();
    let before = f.facts().await;
    let replacement = Secret::generate().unwrap();
    assert!(matches!(
        f.store
            .finish_email(
                f.realm(),
                proof.verifier(),
                browser.verifier(),
                replacement.verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store
            .enroll_password(
                f.realm(),
                current.verifier(),
                "not-used-rejected",
                replacement.verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store
            .begin_account_deletion(
                f.realm(),
                current.verifier(),
                proof.verifier(),
                browser.verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, before);
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_email_challenges")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(pending, 1);
    assert_eq!(
        f.store
            .authenticate(f.realm(), current.verifier())
            .await
            .unwrap()
            .authentication_policy,
        AuthenticationPolicy::ProviderRequired
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn validation_and_inventory_recheck_original_idle_after_an_unchanged_provider_configuration_wait(
    pool: PgPool,
) {
    for inventory in [false, true] {
        let f = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
        let (_, session) = f
            .sign_in
            .finish(f.mapped("subject", json!({})).await)
            .await
            .unwrap();
        let last_seen: i64 = sqlx::query_scalar("UPDATE auth_sessions SET last_seen_at=clock_timestamp()-interval '30 minutes'+interval '2 seconds' WHERE realm_id=$1 AND token_hash=$2 RETURNING (extract(epoch FROM last_seen_at)*1000000)::bigint")
            .bind(f.realm()).bind(session.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
        let before = f.facts().await;
        let mut gate = f.pool.begin().await.unwrap();
        sqlx::query("SELECT id FROM auth_oauth_connections WHERE realm_id=$1 FOR UPDATE")
            .bind(f.realm())
            .fetch_one(&mut *gate)
            .await
            .unwrap();
        let store = f.store.clone();
        let realm = f.realm();
        let current = session.verifier();
        let action = tokio::spawn(async move {
            if inventory {
                store.list_sessions(realm, current, None).await.map(|_| ())
            } else {
                store.authenticate(realm, current).await.map(|_| ())
            }
        });
        wait_for_lock(&f.pool, "%FOR SHARE OF c%").await;
        f.wait_for_expiry(last_seen + 1_800_000_000).await;
        gate.commit().await.unwrap();
        let result = tokio::time::timeout(Duration::from_secs(5), action)
            .await
            .expect("test infrastructure: source-waiting session operation finishes")
            .unwrap();
        assert!(matches!(result, Err(Error::Unauthorized)));
        let unchanged: i64 = sqlx::query_scalar("SELECT (extract(epoch FROM last_seen_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
            .bind(f.realm()).bind(session.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
        assert_eq!(unchanged, last_seen);
        assert_eq!(f.facts().await, before);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn sensitive_revocation_cannot_outlive_actual_provider_freshness_while_waiting_for_configuration(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let authenticated = f.now_seconds().await - 297;
    let (_, session) = f
        .sign_in
        .finish(
            f.mapped("subject", json!({"auth_time":authenticated}))
                .await,
        )
        .await
        .unwrap();
    let before = f.facts().await;
    let mut gate = f.pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_oauth_connections WHERE realm_id=$1 FOR UPDATE")
        .bind(f.realm())
        .fetch_one(&mut *gate)
        .await
        .unwrap();
    let store = f.store.clone();
    let realm = f.realm();
    let action =
        tokio::spawn(async move { store.revoke_all_sessions(realm, session.verifier()).await });
    wait_for_lock(&f.pool, "%FOR SHARE OF c%").await;
    f.wait_for_expiry((authenticated + 300) * 1_000_000).await;
    gate.commit().await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), action)
        .await
        .expect("test infrastructure: provider freshness waiter finishes")
        .unwrap();
    assert!(matches!(result, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, before);
    let now = f.now_seconds().await;
    let (_, fresh) = f
        .sign_in
        .finish(f.mapped("subject", json!({"auth_time":now})).await)
        .await
        .unwrap();
    f.store
        .revoke_all_sessions(f.realm(), fresh.verifier())
        .await
        .unwrap();
}
