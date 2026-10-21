use super::setup::{allow_jit, fixture, verify};
use auth_core::{Error, Repository, SamlSignIn};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn source_bound_validation_listing_revocation_and_logout_preserve_current_policy(
    pool: PgPool,
) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    let (user, a) = service
        .finish(policy.map(verify(&f, "normal").await).unwrap())
        .await
        .unwrap();
    let (_, b) = service
        .finish(policy.map(verify(&f, "normal").await).unwrap())
        .await
        .unwrap();
    let page = f
        .store
        .list_sessions(user.realm_id, a.verifier(), None)
        .await
        .unwrap();
    assert_eq!(page.sessions.len(), 2);
    let target = page.sessions.iter().find(|s| !s.current).unwrap().id;
    assert!(
        !f.store
            .revoke_session(user.realm_id, a.verifier(), target)
            .await
            .unwrap()
    );
    assert!(matches!(
        f.store.authenticate(user.realm_id, b.verifier()).await,
        Err(Error::Unauthorized)
    ));
    let (_, c) = service
        .finish(policy.map(verify(&f, "normal").await).unwrap())
        .await
        .unwrap();
    f.store
        .revoke_all_sessions(user.realm_id, a.verifier())
        .await
        .unwrap();
    for bearer in [&a, &c] {
        assert!(matches!(
            f.store.authenticate(user.realm_id, bearer.verifier()).await,
            Err(Error::Unauthorized)
        ));
    }
    let (_, d) = service
        .finish(policy.map(verify(&f, "normal").await).unwrap())
        .await
        .unwrap();
    f.store
        .disable_saml_registration(
            user.realm_id,
            f.registration.connection(),
            f.registration.client(),
        )
        .await
        .unwrap();
    assert!(matches!(
        f.store.authenticate(user.realm_id, d.verifier()).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.store
            .list_sessions(user.realm_id, d.verifier(), None)
            .await,
        Err(Error::Unauthorized)
    ));
    f.store.revoke(user.realm_id, d.verifier()).await.unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn old_stored_authentication_cannot_authorize_fresh_controls_or_cross_owner_targets(
    pool: PgPool,
) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    let (user, bearer) = service
        .finish(policy.map(verify(&f, "normal").await).unwrap())
        .await
        .unwrap();
    let (other, other_bearer) = service
        .finish(policy.map(verify(&f, "other").await).unwrap())
        .await
        .unwrap();
    let other_page = f
        .store
        .list_sessions(other.realm_id, other_bearer.verifier(), None)
        .await
        .unwrap();
    assert!(
        !f.store
            .revoke_session(user.realm_id, bearer.verifier(), other_page.sessions[0].id)
            .await
            .unwrap()
    );
    assert!(
        f.store
            .authenticate(other.realm_id, other_bearer.verifier())
            .await
            .is_ok()
    );
    sqlx::query("UPDATE auth_sessions SET authenticated_at=clock_timestamp()-interval '6 minutes' WHERE realm_id=$1 AND token_hash=$2")
        .bind(user.realm_id).bind(bearer.verifier().as_slice()).execute(&f.pool).await.unwrap();
    assert!(
        f.store
            .authenticate(user.realm_id, bearer.verifier())
            .await
            .is_ok()
    );
    assert!(matches!(
        f.store
            .revoke_all_sessions(user.realm_id, bearer.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    f.store
        .revoke(user.realm_id, bearer.verifier())
        .await
        .unwrap();
}

#[sqlx::test(migrations = "./migrations")]
async fn signed_session_limit_never_extends_a_shorter_database_absolute_policy(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    sqlx::query("ALTER TABLE auth_sessions ALTER COLUMN expires_at SET DEFAULT (clock_timestamp()+interval '10 minutes')")
        .execute(&f.pool).await.unwrap();
    let proof = verify(&f, "normal").await;
    let signed_limit = proof.session_expires_at_us();
    let (user, bearer) = SamlSignIn::new(f.store.clone())
        .finish(policy.map(proof).unwrap())
        .await
        .unwrap();
    let (remaining,stored): (f64,i64) = sqlx::query_as("SELECT extract(epoch FROM expires_at-clock_timestamp())::float8,(extract(epoch FROM expires_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
        .bind(user.realm_id).bind(bearer.verifier().as_slice()).fetch_one(&f.pool).await.unwrap();
    assert!(remaining > 590.0 && remaining <= 600.0);
    assert!(stored < signed_limit);
}
