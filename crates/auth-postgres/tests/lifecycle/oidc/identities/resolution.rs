use super::setup::Fixture;
use crate::support::signed_in;
use auth_core::*;
use serde_json::json;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn missing_optional_profile_does_not_lock_out_bound_subject_but_cannot_provision_a_new_owner(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let (original, _) = f
        .sign_in
        .finish(f.mapped("known", json!({})).await)
        .await
        .unwrap();
    let (same,_) = f.sign_in.finish(f.mapped("known",json!({"name":null,"preferred_username":"not-selected","email":"not-a-fallback@example.test"})).await).await.unwrap();
    assert_eq!(same, original);
    assert!(matches!(
        f.sign_in
            .finish(
                f.mapped(
                    "new",
                    json!({"name":null,"preferred_username":"not-selected"})
                )
                .await
            )
            .await,
        Err(Error::Unauthorized)
    ));
    f.reconfigure(OidcJitPolicy::Deny).await;
    let (same, _) = f
        .sign_in
        .finish(f.mapped("known", json!({"name":null})).await)
        .await
        .unwrap();
    assert_eq!(same, original);
    assert_eq!(f.facts().await, (1, 1, 3, 3, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn explicit_jit_creates_provider_only_owner_and_genuine_source_without_fabricated_freshness(
    pool: PgPool,
) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let mapped = f
        .mapped(
            "subject",
            json!({"email":"provider@example.test","email_verified":true}),
        )
        .await;
    let (user, session) = f.sign_in.finish(mapped).await.unwrap();
    assert_eq!(
        user.authentication_policy,
        AuthenticationPolicy::ProviderRequired
    );
    assert_eq!(user.email, None);
    assert_eq!(user.display_name.as_deref(), Some("Provider display"));
    assert_eq!(
        f.store
            .authenticate(f.realm(), session.verifier())
            .await
            .unwrap(),
        user
    );
    let page = f
        .store
        .list_sessions(f.realm(), session.verifier(), None)
        .await
        .unwrap();
    assert_eq!(page.sessions.len(), 1);
    assert_eq!(page.sessions[0].authenticated_at_ms, None);
    let source: (String, Option<uuid::Uuid>, Option<uuid::Uuid>) = sqlx::query_as(
        "SELECT authentication_method,oidc_identity_id,oidc_revision FROM auth_sessions",
    )
    .fetch_one(&f.pool)
    .await
    .unwrap();
    assert_eq!(source.0, "oidc");
    assert!(source.1.is_some());
    assert_eq!(source.2, Some(f.policy.configuration().revision()));
    assert!(
        matches!(
            f.store
                .revoke_all_sessions(f.realm(), session.verifier())
                .await,
            Err(Error::Unauthorized)
        ),
        "issuance cannot fabricate fresh authentication"
    );
    assert_eq!(f.facts().await, (1, 1, 1, 1, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn jit_deny_blocks_new_subject_but_existing_subject_resolves_after_reconfiguration(
    pool: PgPool,
) {
    let mut f = Fixture::new(pool, OidcJitPolicy::Deny).await;
    assert!(matches!(
        f.sign_in.finish(f.mapped("subject", json!({})).await).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (0, 0, 0, 0, 0));
    f.reconfigure(OidcJitPolicy::Allow).await;
    let (first, old) = f
        .sign_in
        .finish(f.mapped("subject", json!({})).await)
        .await
        .unwrap();
    f.reconfigure(OidcJitPolicy::Deny).await;
    assert!(matches!(
        f.store.authenticate(f.realm(), old.verifier()).await,
        Err(Error::Unauthorized)
    ));
    let (same, new) = f
        .sign_in
        .finish(
            f.mapped("subject", json!({"name":"Changed provider profile"}))
                .await,
        )
        .await
        .unwrap();
    assert_eq!(
        same, first,
        "repeat sign-in preserves local display metadata and owner"
    );
    f.store
        .authenticate(f.realm(), new.verifier())
        .await
        .unwrap();
    assert!(matches!(
        f.sign_in
            .finish(f.mapped("new-subject", json!({})).await)
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(f.facts().await, (1, 1, 2, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn provider_verified_matching_email_never_merges_or_claims_the_mailbox_owner(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let old = signed_in(&f.store, f.realm(), "match@example.test").await;
    let mailbox = f
        .store
        .authenticate(f.realm(), old.verifier())
        .await
        .unwrap();
    let (provider, new) = f
        .sign_in
        .finish(
            f.mapped(
                "subject",
                json!({"email":"match@example.test","email_verified":true}),
            )
            .await,
        )
        .await
        .unwrap();
    assert_ne!(provider.id, mailbox.id);
    assert_eq!(provider.email, None);
    assert_eq!(
        f.store
            .authenticate(f.realm(), old.verifier())
            .await
            .unwrap(),
        mailbox
    );
    assert_eq!(
        f.store
            .authenticate(f.realm(), new.verifier())
            .await
            .unwrap(),
        provider
    );
    assert_eq!(f.facts().await, (2, 1, 2, 2, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn actual_provider_authentication_time_can_authorize_owned_session_revocation(pool: PgPool) {
    let f = Fixture::new(pool, OidcJitPolicy::Allow).await;
    let now = f.now_seconds().await;
    let (user, first) = f
        .sign_in
        .finish(f.mapped("subject", json!({"auth_time":now})).await)
        .await
        .unwrap();
    let (_, second) = f
        .sign_in
        .finish(f.mapped("subject", json!({"auth_time":now})).await)
        .await
        .unwrap();
    let page = f
        .store
        .list_sessions(f.realm(), first.verifier(), None)
        .await
        .unwrap();
    assert_eq!(page.sessions.len(), 2);
    assert!(
        page.sessions
            .iter()
            .all(|s| s.authenticated_at_ms == Some(now * 1000))
    );
    f.store
        .revoke_all_sessions(f.realm(), first.verifier())
        .await
        .unwrap();
    for session in [first, second] {
        assert!(matches!(
            f.store.authenticate(f.realm(), session.verifier()).await,
            Err(Error::Unauthorized)
        ));
    }
    assert_eq!(f.facts().await, (1, 1, 2, 3, 0));
    assert_eq!(
        user.authentication_policy,
        AuthenticationPolicy::ProviderRequired
    );
}
