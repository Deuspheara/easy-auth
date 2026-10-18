use super::session_id;
use crate::support::{realm, signed_in};
use auth_core::Repository;
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn current_schema_rejects_unbounded_kinds_unsupported_link_facts_and_missing_attribution(
    pool: PgPool,
) {
    let (store, realm) = realm(pool.clone()).await;
    let current = signed_in(&store, realm, "alice@example.com").await;
    let user = store.authenticate(realm, current.verifier()).await.unwrap();
    let session = session_id(&pool, current.verifier()).await;
    for kind in [
        "identity_linked".to_owned(),
        "password_reset\nsecret-payload".into(),
        "x".repeat(4096),
    ] {
        let error = sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,$2,$3)")
            .bind(realm)
            .bind(user.id)
            .bind(kind)
            .execute(&pool)
            .await
            .unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    for (kind, actor, target, version, erased) in [
        ("password_enrolled", None, None::<uuid::Uuid>, 1, false),
        ("session_revoked", Some(session), None, 1, false),
        ("password_reset", None, None, 2, false),
        ("password_reset", Some(session), None, 1, false),
        ("password_reset", None, None, 1, true),
        ("account_deleted", None, None, 1, false),
    ] {
        let error=sqlx::query("INSERT INTO auth_audit(realm_id,user_id,kind,actor_session_id,session_id,schema_version,subject_erased) VALUES ($1,$2,$3,$4,$5,$6,$7)")
            .bind(realm).bind(user.id).bind(kind).bind(actor).bind(target).bind(version as i16).bind(erased).execute(&pool).await.unwrap_err();
        assert_eq!(
            error.as_database_error().unwrap().code().as_deref(),
            Some("23514")
        );
    }
    // Old replicas cannot silently keep writing incomplete current-version lifecycle facts.
    let error = sqlx::query(
        "INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,$2,'email_authenticated')",
    )
    .bind(realm)
    .bind(user.id)
    .execute(&pool)
    .await
    .unwrap_err();
    assert_eq!(
        error.as_database_error().unwrap().code().as_deref(),
        Some("23514")
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_audit")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}
