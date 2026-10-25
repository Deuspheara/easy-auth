use super::*;
use auth_core::Error;

#[sqlx::test]
async fn durable_code_state_and_audit_reject_inconsistent_or_cross_owner_facts(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    let pending = f.prepare().await.unwrap();
    let code = f.approve(&pending).await;
    for assignment in [
        "code_expires_at_us=NULL",
        "nonce=NULL",
        "pkce_challenge=NULL",
        "subject='00000000-0000-0000-0000-000000000001'",
        "code_hash=decode('00','hex')",
        "status='consumed'",
        "authentication_method='legacy_unknown'",
    ] {
        let error = sqlx::query(&format!(
            "UPDATE auth_issuer_authorizations SET {assignment} WHERE realm_id=$1"
        ))
        .bind(f.realm)
        .execute(&pool)
        .await
        .unwrap_err();
        assert!(matches!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514" | "23503")
        ));
    }
    let other = crate::support::signed_in(&f.store, f.realm, "other@example.test").await;
    let other_owner = f
        .store
        .authenticate(f.realm, other.verifier())
        .await
        .unwrap()
        .id;
    let error = sqlx::query(
        "UPDATE auth_audit SET user_id=$2 WHERE realm_id=$1 AND kind='issuer_authorized'",
    )
    .bind(f.realm)
    .bind(other_owner)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23503")
    );
    let error = sqlx::query("UPDATE auth_audit SET schema_version=0,actor_session_id=NULL WHERE realm_id=$1 AND kind='issuer_authorized'")
        .bind(f.realm).execute(&pool).await.unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    f.service
        .redeem(
            &f.authentication(),
            &code,
            &f.redirect,
            &f.pkce,
            "127.0.0.1",
        )
        .await
        .unwrap();
}

#[sqlx::test]
async fn mailbox_credentials_cannot_authorize_provider_or_passkey_required_owners(pool: PgPool) {
    let f = Fixture::new(&pool, false).await;
    for policy in ["provider_required", "passkey_required"] {
        sqlx::query("UPDATE auth_users SET authentication_policy=$2 WHERE realm_id=$1")
            .bind(f.realm)
            .bind(policy)
            .execute(&pool)
            .await
            .unwrap();
        assert!(matches!(f.prepare().await, Err(Error::Unauthorized)));
        assert_eq!(f.count(&pool, "auth_issuer_authorizations").await, 0);
    }
    sqlx::query("UPDATE auth_users SET authentication_policy='mailbox' WHERE realm_id=$1")
        .bind(f.realm)
        .execute(&pool)
        .await
        .unwrap();
    sqlx::query(
        "UPDATE auth_sessions SET authentication_method='legacy_unknown' WHERE realm_id=$1",
    )
    .bind(f.realm)
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(f.prepare().await, Err(Error::Unauthorized)));
    sqlx::query("UPDATE auth_sessions SET authentication_method='email' WHERE realm_id=$1")
        .bind(f.realm)
        .execute(&pool)
        .await
        .unwrap();
    f.prepare().await.unwrap();
}
