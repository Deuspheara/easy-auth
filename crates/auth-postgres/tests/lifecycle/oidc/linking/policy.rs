use super::setup::*;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn unlink_cooldown_blocks_a_preverified_jit_replacement_owner(pool: PgPool) {
    let f = Fixture::with_jit(pool, OidcJitPolicy::Allow).await;
    let (owner, current) = f.local("owner@example.test").await;
    let linked = f.linked(&owner, &current, "subject").await;
    let held = f.prepare(OAuthPurpose::SignIn, "subject", json!({})).await;
    let mapped = f.complete(&held).await.unwrap();
    f.linking
        .unlink(f.realm(), &current, linked.id)
        .await
        .unwrap();
    let before = f.facts().await;
    assert!(matches!(
        OidcSignIn::new(f.store.clone()).finish(mapped).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, before);
    let cooldowns:i64=sqlx::query_scalar("SELECT count(*) FROM auth_oidc_deleted_subjects WHERE realm_id=$1 AND blocked_until>clock_timestamp()").bind(f.realm()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(cooldowns, 1);
    // An unrelated actual signed subject remains eligible under JIT Allow.
    let (other, _) = f.login("unrelated-subject").await.unwrap();
    assert_ne!(other.id, owner.id);
}

#[sqlx::test(migrations = "./migrations")]
async fn linked_mailbox_sessions_have_current_source_inventory_and_no_local_credential_shortcut(
    pool: PgPool,
) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    let linked = f.linked(&owner, &current, "subject").await;
    let (_, provider_session) = f.login("subject").await.unwrap();
    let sessions = f
        .store
        .list_sessions(f.realm(), provider_session.verifier(), None)
        .await
        .unwrap();
    assert_eq!(sessions.sessions.len(), 2);
    assert_eq!(sessions.sessions.iter().filter(|s| s.current).count(), 1);
    let new = Secret::generate().unwrap();
    assert!(matches!(
        f.store
            .enroll_password(
                f.realm(),
                provider_session.verifier(),
                "not-a-hash",
                new.verifier()
            )
            .await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.linking
            .unlink(f.realm(), &provider_session, linked.id)
            .await,
        Err(Error::Unauthorized)
    ));
    let c = f.policy.configuration();
    f.store
        .disable_oauth_connection(c.realm(), c.connection(), c.client())
        .await
        .unwrap();
    assert!(matches!(
        f.store
            .authenticate(f.realm(), provider_session.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(
        f.store
            .authenticate(f.realm(), current.verifier())
            .await
            .unwrap(),
        owner
    );
    f.linking
        .unlink(f.realm(), &current, linked.id)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn operator_policy_changes_cannot_turn_an_old_jit_identity_into_a_mailbox_link(pool: PgPool) {
    let f = Fixture::with_jit(pool, OidcJitPolicy::Allow).await;
    let (owner, current) = f.login("subject").await.unwrap();
    // Negative privileged fixture only; no contact/policy-transition API is claimed.
    sqlx::query("UPDATE auth_users SET authentication_policy='mailbox',email='changed@example.test',email_verified_at=clock_timestamp() WHERE realm_id=$1 AND id=$2").bind(f.realm()).bind(owner.id).execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.store.authenticate(f.realm(), current.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(f.login("subject").await, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn explicit_link_does_not_relax_a_stronger_account_policy(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let (owner, current) = f.local("owner@example.test").await;
    f.linked(&owner, &current, "subject").await;
    let a = f.prepare(OAuthPurpose::SignIn, "subject", json!({})).await;
    let mapped = f.complete(&a).await.unwrap();
    sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2").bind(f.realm()).bind(owner.id).execute(&f.pool).await.unwrap();
    assert!(matches!(
        OidcSignIn::new(f.store.clone()).finish(mapped).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(f.login("subject").await, Err(Error::Unauthorized)));
    assert_eq!(f.facts().await, (1, 1, 1, 2, 1));
}
