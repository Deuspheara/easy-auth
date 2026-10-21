use super::setup::{allow_jit, fixture, verify};
use auth_core::SamlSignIn;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn session_provenance_and_closed_audit_shape_cannot_cross_owners_or_methods(pool: PgPool) {
    let (mut f, policy) = fixture(pool).await;
    let policy = allow_jit(&mut f, &policy).await;
    let service = SamlSignIn::new(f.store.clone());
    let (a, a_bearer) = service
        .finish(policy.map(verify(&f, "a").await).unwrap())
        .await
        .unwrap();
    let (b, _) = service
        .finish(policy.map(verify(&f, "b").await).unwrap())
        .await
        .unwrap();
    let other_identity: uuid::Uuid =
        sqlx::query_scalar("SELECT id FROM auth_saml_identities WHERE realm_id=$1 AND user_id=$2")
            .bind(b.realm_id)
            .bind(b.id)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    let result = sqlx::query(
        "UPDATE auth_sessions SET saml_identity_id=$3 WHERE realm_id=$1 AND token_hash=$2",
    )
    .bind(a.realm_id)
    .bind(a_bearer.verifier().as_slice())
    .bind(other_identity)
    .execute(&f.pool)
    .await;
    assert_eq!(
        result
            .unwrap_err()
            .as_database_error()
            .unwrap()
            .code()
            .as_deref(),
        Some("23503")
    );
    for statement in [
        "UPDATE auth_sessions SET authentication_method='email' WHERE authentication_method='saml'",
        "UPDATE auth_sessions SET saml_revision=NULL WHERE authentication_method='saml'",
        "UPDATE auth_audit SET actor_session_id=session_id WHERE kind='saml_authenticated'",
        "UPDATE auth_audit SET session_id=NULL WHERE kind='saml_authenticated'",
        "UPDATE auth_audit SET kind='unbounded_provider_event' WHERE kind='saml_authenticated'",
    ] {
        let error = sqlx::query(statement).execute(&f.pool).await.unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
}
