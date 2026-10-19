use super::*;
use auth_core::Error;
use std::time::Duration;

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_finish_has_one_key_update_session_and_audit(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    let (a, b) = tokio::join!(
        f.flow.finish(&f.enrollment.browser, SOURCE, id, &response),
        f.flow.finish(&f.enrollment.browser, SOURCE, id, &response)
    );
    assert_ne!(a.is_ok(), b.is_ok());
    assert_eq!(authentication_count(&pool).await, 1);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_sessions WHERE authentication_method='passkey'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn audit_failure_rolls_back_consumption_key_update_and_session(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    sqlx::raw_sql("CREATE FUNCTION fail_passkey_login() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='passkey_authenticated' THEN RAISE EXCEPTION 'test audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER fail_passkey_login BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION fail_passkey_login();").execute(&pool).await.unwrap();
    assert!(matches!(
        f.flow
            .finish(&f.enrollment.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unavailable)
    ));
    let (count, unused): (i64, bool) =
        sqlx::query_as("SELECT count(*),bool_and(last_used_at IS NULL) FROM auth_passkeys")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 1);
    assert!(unused);
    let sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_sessions WHERE authentication_method='passkey'",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(sessions, 0);
    sqlx::raw_sql(
        "DROP TRIGGER fail_passkey_login ON auth_audit; DROP FUNCTION fail_passkey_login();",
    )
    .execute(&pool)
    .await
    .unwrap();
    assert!(
        f.flow
            .finish(&f.enrollment.browser, SOURCE, id, &response)
            .await
            .is_ok()
    );
    assert_eq!(authentication_count(&pool).await, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn proof_cannot_consume_a_different_ceremony_or_overwrite_a_changed_key(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (first, response) = f.begin().await;
    let (second, _) = f.begin().await;
    let proof = f.proof(first, &response).await;
    let session = Secret::generate().unwrap();
    assert!(matches!(
        f.enrollment
            .store
            .commit_authentication(&f.request(second), proof, session.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    let proof = f.proof(first, &response).await;
    // Valid JSON with changed bytes models an intervening credential update.
    sqlx::query("UPDATE auth_passkeys SET credential=credential || decode('20','hex')")
        .execute(&pool)
        .await
        .unwrap();
    assert!(matches!(
        f.enrollment
            .store
            .commit_authentication(&f.request(first), proof, session.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    assert_eq!(authentication_count(&pool).await, 0);
    assert!(
        f.enrollment
            .store
            .authenticate(f.enrollment.realm, session.verifier())
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn expiry_is_rechecked_after_waiting_for_the_owner_lock(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    let proof = f.proof(id, &response).await;
    let session = Secret::generate().unwrap();
    let mut gate = pool.begin().await.unwrap();
    sqlx::query("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE")
        .bind(f.enrollment.realm)
        .bind(f.owner)
        .execute(&mut *gate)
        .await
        .unwrap();
    let store = f.enrollment.store.clone();
    let request = f.request(id);
    let verifier = session.verifier();
    let finish =
        tokio::spawn(async move { store.commit_authentication(&request, proof, verifier).await });
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE 'SELECT id FROM auth_users%FOR UPDATE%')").fetch_one(&pool).await.unwrap();
            if waiting { break; } tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.unwrap();
    sqlx::query("UPDATE auth_passkey_authentications SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1").bind(id).execute(&mut *gate).await.unwrap();
    gate.commit().await.unwrap();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), finish)
            .await
            .unwrap()
            .unwrap(),
        Err(Error::Unauthorized)
    ));
    assert_eq!(authentication_count(&pool).await, 0);
    assert!(
        f.enrollment
            .store
            .authenticate(f.enrollment.realm, session.verifier())
            .await
            .is_err()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn revoke_all_and_deletion_cancel_owned_pending_authentication(pool: PgPool) {
    let mut f = SignIn::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    f.enrollment
        .store
        .revoke_all_sessions(f.enrollment.realm, f.enrollment.session.verifier())
        .await
        .unwrap();
    assert!(matches!(
        f.flow
            .finish(&f.enrollment.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    // A new valid private-key proof can authenticate again, as with other login methods.
    let (id, response) = f.begin().await;
    let current = f
        .flow
        .finish(&f.enrollment.browser, SOURCE, id, &response)
        .await
        .unwrap();
    let (id, response) = f.begin().await;
    let verified = f.proof(id, &response).await;
    let proof = Secret::generate().unwrap();
    f.enrollment
        .store
        .begin_account_deletion(
            f.enrollment.realm,
            current.verifier(),
            proof.verifier(),
            f.enrollment.browser.verifier(),
        )
        .await
        .unwrap();
    f.enrollment
        .store
        .finish_account_deletion(
            f.enrollment.realm,
            current.verifier(),
            proof.verifier(),
            f.enrollment.browser.verifier(),
        )
        .await
        .unwrap();
    let session = Secret::generate().unwrap();
    assert!(matches!(
        f.enrollment
            .store
            .commit_authentication(&f.request(id), verified, session.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey_authentications")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
    let erased:bool=sqlx::query_scalar("SELECT subject_erased AND user_id IS NULL AND session_id IS NULL FROM auth_audit WHERE kind='passkey_authenticated'").fetch_one(&pool).await.unwrap();
    assert!(erased);
}
