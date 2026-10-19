use super::*;
use auth_core::{Error, PasskeyRepository, Repository};

#[sqlx::test(migrations = "./migrations")]
async fn rp_wide_duplicate_in_another_realm_rolls_back_consumption(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    let request = f.request(id);
    let state = f.store.load_enrollment(&request).await.unwrap();
    let credential = f.service.verify_registration(&response, state).unwrap();
    let other_realm = Uuid::new_v4();
    f.store.ensure_realm(other_realm).await.unwrap();
    let other_session = signed_in(&f.store, other_realm, "bob@example.com").await;
    let other = f
        .store
        .authenticate(other_realm, other_session.verifier())
        .await
        .unwrap();
    // Seed an already owned, verified credential in another realm sharing this RP.
    sqlx::query("INSERT INTO auth_passkeys(realm_id,id,user_id,rp_id,credential_id,credential,label) VALUES ($1,$2,$3,$4,$5,$6,'existing')")
        .bind(other_realm).bind(Uuid::new_v4()).bind(other.id).bind(credential.rp_id())
        .bind(credential.credential_id()).bind(credential.encode_for_database().unwrap())
        .execute(&pool).await.unwrap();
    assert!(matches!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let pending: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_passkey_enrollments WHERE realm_id=$1 AND id=$2",
    )
    .bind(f.realm)
    .bind(id)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(pending, 1);
    let own: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1")
        .bind(f.realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(own, 0);
    assert_eq!(
        f.store
            .authenticate(other_realm, other_session.verifier())
            .await
            .unwrap()
            .id,
        other.id
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn concurrent_last_slot_cannot_exceed_account_credential_limit(pool: PgPool) {
    let mut f = Fixture::new(pool.clone()).await;
    let (first, response, mut token) = f.begin_with_token().await;
    f.enrollment
        .finish(&f.session, &f.browser, SOURCE, first, &response)
        .await
        .unwrap();
    f.session = f.sign_in_with_key(&mut token).await;
    for _ in 0..8 {
        let (id, response) = f.begin().await;
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await
            .unwrap();
    }
    // Isolate the credential-count boundary from the independently tested start admission cap.
    sqlx::query("DELETE FROM auth_rate_buckets WHERE realm_id=$1")
        .bind(f.realm)
        .execute(&pool)
        .await
        .unwrap();
    let (id_a, response_a) = f.begin().await;
    let (id_b, response_b) = f.begin().await;
    let (a, b) = tokio::join!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id_a, &response_a),
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id_b, &response_b)
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let denied = if a.is_ok() { b } else { a };
    assert!(matches!(denied, Err(Error::RateLimited)));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1")
        .bind(f.realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 10);
}

#[sqlx::test(migrations = "./migrations")]
async fn deletion_cascades_credentials_state_and_audit_attribution(pool: PgPool) {
    let mut f = Fixture::new(pool.clone()).await;
    let (id, response, mut token) = f.begin_with_token().await;
    f.enrollment
        .finish(&f.session, &f.browser, SOURCE, id, &response)
        .await
        .unwrap();
    f.session = f.sign_in_with_key(&mut token).await;
    f.begin().await;
    let proof = Secret::generate().unwrap();
    f.store
        .begin_account_deletion(
            f.realm,
            f.session.verifier(),
            proof.verifier(),
            f.browser.verifier(),
        )
        .await
        .unwrap();
    f.store
        .finish_account_deletion(
            f.realm,
            f.session.verifier(),
            proof.verifier(),
            f.browser.verifier(),
        )
        .await
        .unwrap();
    for table in ["auth_passkeys", "auth_passkey_enrollments"] {
        let count: i64 =
            sqlx::query_scalar(&format!("SELECT count(*) FROM {table} WHERE realm_id=$1"))
                .bind(f.realm)
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(count, 0);
    }
    let erased:bool=sqlx::query_scalar("SELECT subject_erased AND user_id IS NULL AND actor_session_id IS NULL FROM auth_audit WHERE realm_id=$1 AND kind='passkey_enrolled'")
        .bind(f.realm).fetch_one(&pool).await.unwrap();
    assert!(erased);
    let owned_buckets:i64=sqlx::query_scalar("SELECT count(*) FROM auth_rate_buckets WHERE realm_id=$1 AND dimension IN ('passkey_enroll_user','passkey_finish_user')")
        .bind(f.realm).fetch_one(&pool).await.unwrap();
    assert_eq!(owned_buckets, 0);
}
