use super::setup::{allow_jit, facts, fixture, verify};
use auth_core::{AuthenticationPolicy, Error, Repository, SamlJitPolicy, SamlSignIn};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn default_deny_and_unpersisted_allow_cannot_create_any_authority_or_replay_row(
    pool: PgPool,
) {
    let (f, policy) = fixture(pool).await;
    let service = SamlSignIn::new(f.store.clone());
    let mapped = policy.map(verify(&f, "normal").await).unwrap();
    assert!(matches!(
        service.finish(mapped).await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (0, 0, 0, 0, 0));
    let unpersisted = policy.with_jit(SamlJitPolicy::Allow);
    assert!(matches!(
        service
            .finish(unpersisted.map(verify(&f, "normal").await).unwrap())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (0, 0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn signed_jit_commits_exact_identity_replay_source_session_and_audit_together(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    let proof = verify(&f, "Opaque-Subject").await;
    let admission = proof.expires_at_us();
    let authn = proof.authenticated_at_us();
    let session_limit = proof.session_expires_at_us();
    let (user, bearer) = service.finish(policy.map(proof).unwrap()).await.unwrap();
    assert_eq!(
        user.authentication_policy,
        AuthenticationPolicy::ProviderRequired
    );
    assert_eq!(user.email, None);
    assert_eq!(user.display_name.as_deref(), Some("Opaque-Subject"));
    assert_eq!(
        f.store
            .authenticate(f.registration.realm(), bearer.verifier())
            .await
            .unwrap(),
        user
    );
    let (method,stored_authn,stored_expiry,source_revision): (String,i64,i64,uuid::Uuid) = sqlx::query_as("SELECT authentication_method,(extract(epoch FROM authenticated_at)*1000000)::bigint,(extract(epoch FROM expires_at)*1000000)::bigint,saml_revision FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
        .bind(user.realm_id).bind(bearer.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    assert_eq!(method, "saml");
    assert_eq!(stored_authn, authn);
    assert_eq!(stored_expiry, session_limit);
    assert!(stored_expiry > admission);
    assert_eq!(source_revision, f.registration.revision());
    let kind: String =
        sqlx::query_scalar("SELECT kind FROM auth_audit WHERE realm_id=$1 AND user_id=$2")
            .bind(user.realm_id)
            .bind(user.id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(kind, "saml_authenticated");
    assert_eq!(facts(&f).await, (1, 1, 1, 2, 1));
    let page = f
        .store
        .list_sessions(user.realm_id, bearer.verifier(), None)
        .await
        .unwrap();
    assert_eq!(page.sessions.len(), 1);
    assert!(page.sessions[0].current);
    assert_eq!(page.sessions[0].authenticated_at_ms, Some(authn / 1000));
}

#[sqlx::test(migrations = "./migrations")]
async fn a_known_subject_resolves_under_deny_after_reconfiguration_and_old_sessions_fail(
    pool: PgPool,
) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    let (original, old) = service
        .finish(policy.map(verify(&f, "known").await).unwrap())
        .await
        .unwrap();
    let next = f
        .store
        .configure_saml_identity_policy(
            &policy.with_jit(SamlJitPolicy::Deny),
            &super::super::signed_idp::trust(),
        )
        .await
        .unwrap();
    f.registration = next.registration().clone();
    f.flow = auth_core::SamlTransactions::new(f.registration.clone(), f.store.clone());
    assert!(matches!(
        f.store
            .authenticate(original.realm_id, old.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    let (same, current) = service
        .finish(next.map(verify(&f, "known").await).unwrap())
        .await
        .unwrap();
    assert_eq!(same, original);
    assert!(
        f.store
            .authenticate(original.realm_id, current.verifier())
            .await
            .is_ok()
    );
    assert!(matches!(
        service
            .finish(next.map(verify(&f, "new").await).unwrap())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(facts(&f).await, (1, 1, 2, 4, 2));
}
