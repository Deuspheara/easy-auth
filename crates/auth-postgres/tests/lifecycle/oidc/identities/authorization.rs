use super::setup::Fixture;
use crate::support::signed_in;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;
use uuid::Uuid;

#[sqlx::test(migrations = "./migrations")]
async fn unpersisted_policy_changes_and_pre_disable_proofs_cannot_provision(pool: PgPool) {
    let mut f = Fixture::new(pool, OidcJitPolicy::Deny).await;
    f.policy = f.policy.clone().with_jit(OidcJitPolicy::Allow);
    assert!(matches!(
        f.sign_in.finish(f.mapped("subject", json!({})).await).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.reconfigure(OidcJitPolicy::Allow).await;
    let first = f.mapped("subject", json!({})).await;
    let second = f.mapped("subject", json!({})).await;
    let c = f.policy.configuration();
    f.store
        .disable_oauth_connection(c.realm(), c.connection(), c.client())
        .await
        .unwrap();
    assert!(matches!(
        f.sign_in.finish(first).await,
        Err(Error::Unauthorized)
    ));
    f.reconfigure(OidcJitPolicy::Allow).await;
    f.store
        .enable_oauth_connection(f.policy.configuration())
        .await
        .unwrap();
    assert!(matches!(
        f.sign_in.finish(second).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn linking_purpose_neither_use_case_nor_repository_can_turn_into_signin(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let session = signed_in(&f.store, f.realm(), "link-owner@example.test").await;
    let user = f
        .store
        .authenticate(f.realm(), session.verifier())
        .await
        .unwrap();
    for direct in [false, true] {
        let mapped = f
            .mapped_for(
                "subject",
                json!({}),
                OAuthPurpose::Link {
                    user: user.id,
                    session: session.verifier(),
                },
                None,
            )
            .await;
        if direct {
            assert!(matches!(
                f.store
                    .finish_oidc_identity(mapped, Secret::generate().unwrap().verifier())
                    .await,
                Err(Error::Unauthorized)
            ));
        } else {
            assert!(matches!(
                f.sign_in.finish(mapped).await,
                Err(Error::Unauthorized)
            ));
        }
    }
    assert_eq!(f.facts().await, (1, 0, 1, 1, 0));
    f.store
        .authenticate(f.realm(), session.verifier())
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn same_issuer_subject_and_connection_ids_are_isolated_by_realm_and_local_client(
    pool: PgPool,
) {
    let first = Fixture::new(pool.clone(), OidcJitPolicy::Allow).await;
    let c = first.policy.configuration();
    let second = Fixture::scoped(
        pool.clone(),
        first.store.clone(),
        Uuid::new_v4(),
        c.connection(),
        c.client(),
        OidcJitPolicy::Allow,
    )
    .await;
    let third = Fixture::scoped(
        pool,
        first.store.clone(),
        c.realm(),
        c.connection(),
        Uuid::new_v4(),
        OidcJitPolicy::Allow,
    )
    .await;
    let mut owners = Vec::new();
    for f in [&first, &second, &third] {
        let (user, session) = f
            .sign_in
            .finish(
                f.mapped(
                    "identical-subject",
                    json!({"email":"same@example.test","email_verified":true}),
                )
                .await,
            )
            .await
            .unwrap();
        assert!(!owners.contains(&user.id));
        owners.push(user.id);
        assert_eq!(user.realm_id, f.realm());
        assert_eq!(
            f.store
                .authenticate(f.realm(), session.verifier())
                .await
                .unwrap()
                .id,
            user.id
        );
        if f.realm() != first.realm() {
            assert!(matches!(
                f.store
                    .authenticate(first.realm(), session.verifier())
                    .await,
                Err(Error::Unauthorized)
            ));
        }
    }
    assert_eq!(first.facts().await, (3, 3, 3, 3, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn provider_amr_does_not_override_passkey_policy_and_weak_sessions_cannot_enter_provider_accounts(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (user, current) = f
        .sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    for method in ["email", "password", "legacy_unknown", "passkey"] {
        let weak = Secret::generate().unwrap();
        sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES($1,$2,$3,$4,$5)")
            .bind(f.realm()).bind(Uuid::new_v4()).bind(user.id).bind(weak.verifier().as_slice()).bind(method).execute(&f.pool).await.unwrap();
        assert!(matches!(
            f.store.authenticate(f.realm(), weak.verifier()).await,
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(
        f.store
            .list_sessions(f.realm(), current.verifier(), None)
            .await
            .unwrap()
            .sessions
            .len(),
        1
    );
    let now = f.now_seconds().await;
    let mapped = f
        .mapped("subject", json!({"auth_time":now,"amr":["mfa","hwk"]}))
        .await;
    sqlx::query("UPDATE auth_users SET authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2").bind(f.realm()).bind(user.id).execute(&f.pool).await.unwrap();
    assert!(matches!(
        f.sign_in.finish(mapped).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store.authenticate(f.realm(), current.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (1, 1, 5, 1, 0));
}
