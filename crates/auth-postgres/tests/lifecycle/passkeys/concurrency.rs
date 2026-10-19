use super::*;
use auth_core::{Error, PasskeyRepository, Repository};

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_completion_has_one_credential_and_one_audit_fact(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    let (a, b) = tokio::join!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response),
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    for table in ["auth_passkeys", "auth_audit"] {
        let sql = if table == "auth_audit" {
            "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_enrolled'"
        } else {
            "SELECT count(*) FROM auth_passkeys WHERE realm_id=$1"
        };
        let count: i64 = sqlx::query_scalar(sql)
            .bind(f.realm)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn failed_audit_rolls_back_credential_and_state_consumption(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    sqlx::query(
        "ALTER TABLE auth_audit ADD CONSTRAINT test_fail_passkey CHECK (kind<>'passkey_enrolled')",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(matches!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unavailable)
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1")
        .bind(f.realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    sqlx::query("ALTER TABLE auth_audit DROP CONSTRAINT test_fail_passkey")
        .execute(&pool)
        .await
        .unwrap();
    assert!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn rechecks_session_and_exact_state_after_external_verification(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    let request = f.request(id);
    let state = f.store.load_enrollment(&request).await.unwrap();
    let encoded = state.encode_for_database().unwrap();
    let credential = f.service.verify_registration(&response, state).unwrap();
    sqlx::query("UPDATE auth_passkey_enrollments SET private_state=private_state || ' '::bytea WHERE realm_id=$1 AND id=$2")
        .bind(f.realm).bind(id).execute(&pool).await.unwrap();
    assert!(matches!(
        f.store
            .commit_enrollment(&request, &encoded, credential)
            .await,
        Err(Error::Unauthorized)
    ));
    // The changed encoding is still valid JSON, but the original verified snapshot cannot commit.
    let state = f.store.load_enrollment(&request).await.unwrap();
    let encoded = state.encode_for_database().unwrap();
    let credential = f.service.verify_registration(&response, state).unwrap();
    f.store.revoke(f.realm, f.session.verifier()).await.unwrap();
    assert!(matches!(
        f.store
            .commit_enrollment(&request, &encoded, credential)
            .await,
        Err(Error::Unauthorized)
    ));
}
