use super::*;
use auth_core::{Error, PasskeyRepository, Repository};

#[sqlx::test(migrations = "./migrations")]
async fn valid_signed_enrollment_is_bound_single_use_and_audited(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    let wrong_browser = Secret::generate().unwrap();
    assert!(matches!(
        f.enrollment
            .finish(&f.session, &wrong_browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let sibling = signed_in(&f.store, f.realm, "alice@example.com").await;
    assert!(matches!(
        f.enrollment
            .finish(&sibling, &f.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let other = signed_in(&f.store, f.realm, "bob@example.com").await;
    assert!(matches!(
        f.enrollment
            .finish(&other, &f.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let foreign = Uuid::new_v4();
    f.store.ensure_realm(foreign).await.unwrap();
    let enrollment = PasskeyEnrollment::new(foreign, f.service.clone(), f.store.clone());
    assert!(matches!(
        enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let credential = f
        .enrollment
        .finish(&f.session, &f.browser, SOURCE, id, &response)
        .await
        .unwrap();
    assert!(matches!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let (label, rp, stored): (String, String, Vec<u8>) = sqlx::query_as(
        "SELECT label,rp_id,credential FROM auth_passkeys WHERE realm_id=$1 AND id=$2",
    )
    .bind(f.realm)
    .bind(credential)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(label, "Security key");
    assert_eq!(rp, "login.example.com");
    assert!(!stored.is_empty());
    let event: (i16, bool, bool) = sqlx::query_as("SELECT schema_version,actor_session_id IS NOT NULL,session_id IS NULL FROM auth_audit WHERE realm_id=$1 AND kind='passkey_enrolled'")
        .bind(f.realm).fetch_one(&pool).await.unwrap();
    assert_eq!(event, (1, true, true));
    let context = f
        .store
        .enrollment_context(f.realm, f.session.verifier(), f.service.rp_id())
        .await
        .unwrap();
    assert_eq!(context.excluded_credentials.len(), 1);
    assert!(
        f.store
            .authenticate(f.realm, f.session.verifier())
            .await
            .is_ok()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn expiry_revocation_and_revoke_all_cancel_enrollment(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    sqlx::query("UPDATE auth_passkey_enrollments SET expires_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1 AND id=$2")
        .bind(f.realm).bind(id).execute(&pool).await.unwrap();
    assert!(matches!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let (id, response) = f.begin().await;
    f.store.revoke(f.realm, f.session.verifier()).await.unwrap();
    assert!(matches!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await,
        Err(Error::Unauthorized)
    ));
    let f = Fixture::new(pool.clone()).await;
    let (id, response) = f.begin().await;
    f.store
        .revoke_all_sessions(f.realm, f.session.verifier())
        .await
        .unwrap();
    assert!(
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await
            .is_err()
    );
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkey_enrollments WHERE realm_id=$1")
            .bind(f.realm)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "./migrations")]
async fn bounded_pending_and_failed_verifications_spend_admission(pool: PgPool) {
    let f = Fixture::new(pool.clone()).await;
    let mut first = None;
    for _ in 0..3 {
        let pending = f
            .enrollment
            .begin(&f.session, &f.browser, SOURCE, "key")
            .await
            .unwrap();
        first.get_or_insert(pending);
    }
    assert!(matches!(
        f.enrollment
            .begin(&f.session, &f.browser, SOURCE, "key")
            .await,
        Err(Error::RateLimited)
    ));
    let first = first.unwrap();
    let malformed = serde_json::from_value(
        serde_json::json!({"id":"AQ","rawId":"AQ","type":"public-key",
        "response":{"attestationObject":"AA","clientDataJSON":"e30"}}),
    )
    .unwrap();
    for _ in 0..20 {
        assert!(matches!(
            f.enrollment
                .finish(
                    &f.session,
                    &f.browser,
                    SOURCE,
                    first.transaction,
                    &malformed
                )
                .await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        f.enrollment
            .finish(
                &f.session,
                &f.browser,
                SOURCE,
                first.transaction,
                &malformed
            )
            .await,
        Err(Error::RateLimited)
    ));
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE realm_id=$1")
        .bind(f.realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
}
