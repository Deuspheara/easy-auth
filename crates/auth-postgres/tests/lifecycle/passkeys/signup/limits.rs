use super::*;
use auth_core::Error;

#[sqlx::test(migrations = "./migrations")]
async fn invalid_display_names_and_nil_realm_cannot_allocate_pending_identity(pool: PgPool) {
    let f = Signup::new(pool).await;
    for name in ["", "  ", "Bad\nlabel", &"x".repeat(257)] {
        assert!(matches!(
            f.flow.begin(name, &f.browser, SOURCE).await,
            Err(Error::InvalidInput)
        ));
    }
    let nil = PasskeySignup::new(Uuid::nil(), f.service.clone(), f.store.clone());
    assert!(matches!(
        nil.begin("Person", &f.browser, SOURCE).await,
        Err(Error::InvalidInput)
    ));
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey_signups")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn browser_pending_limit_is_atomic_and_expired_signups_are_reclaimed(pool: PgPool) {
    let f = Signup::new(pool).await;
    let (a, b, c, d) = tokio::join!(
        f.flow.begin("Person", &f.browser, SOURCE),
        f.flow.begin("Person", &f.browser, SOURCE),
        f.flow.begin("Person", &f.browser, SOURCE),
        f.flow.begin("Person", &f.browser, SOURCE)
    );
    let results = [a, b, c, d];
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 3);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(Error::RateLimited)))
            .count(),
        1
    );
    sqlx::query("UPDATE auth_passkey_signups SET expires_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1")
        .bind(f.realm).execute(&f.pool).await.unwrap();
    assert!(f.flow.begin("Person", &f.browser, SOURCE).await.is_ok());
    let pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkey_signups WHERE realm_id=$1")
            .bind(f.realm)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(pending, 1);
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
}

#[sqlx::test(migrations = "./migrations")]
async fn realm_pending_limit_applies_across_browsers_and_reclaims_only_expired_state(pool: PgPool) {
    let f = Signup::new(pool).await;
    let pending = f.flow.begin("Person", &f.browser, SOURCE).await.unwrap();
    // Storage-cap fixture only: these copied protocol states are never verified.
    sqlx::query("INSERT INTO auth_passkey_signups(realm_id,id,prospective_user,browser_hash,rp_id,display_name,stage,registration_state) SELECT realm_id,gen_random_uuid(),gen_random_uuid(),sha256(g::text::bytea),rp_id,display_name,stage,registration_state FROM auth_passkey_signups CROSS JOIN generate_series(1,255) g WHERE id=$1")
        .bind(pending.transaction).execute(&f.pool).await.unwrap();
    let peer = Secret::generate().unwrap();
    assert!(matches!(
        f.flow.begin("Person", &peer, SOURCE).await,
        Err(Error::RateLimited)
    ));
    sqlx::query("UPDATE auth_passkey_signups SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1")
        .bind(pending.transaction).execute(&f.pool).await.unwrap();
    assert!(f.flow.begin("Person", &peer, SOURCE).await.is_ok());
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkey_signups WHERE realm_id=$1")
            .bind(f.realm)
            .fetch_one(&f.pool)
            .await
            .unwrap();
    assert_eq!(count, 256);
}

#[sqlx::test(migrations = "./migrations")]
async fn absent_finish_attempts_spend_durable_browser_and_source_budget(pool: PgPool) {
    let f = Signup::new(pool).await;
    let request = f.request(Uuid::new_v4());
    for _ in 0..20 {
        assert!(matches!(
            f.store
                .load_signup_registration(&request, f.service.rp_id())
                .await,
            Err(Error::Unauthorized)
        ));
    }
    assert!(matches!(
        f.store
            .load_signup_registration(&request, f.service.rp_id())
            .await,
        Err(Error::RateLimited)
    ));
    for _ in 0..20 {
        let mut request = f.request(Uuid::new_v4());
        request.browser = Secret::generate().unwrap().verifier();
        assert!(matches!(
            f.store
                .load_signup_authentication(&request, f.service.rp_id())
                .await,
            Err(Error::Unauthorized)
        ));
    }
    let mut request = f.request(Uuid::new_v4());
    request.browser = Secret::generate().unwrap().verifier();
    assert!(matches!(
        f.store
            .load_signup_authentication(&request, f.service.rp_id())
            .await,
        Err(Error::RateLimited)
    ));
    assert_eq!(f.durable_counts().await, (0, 0, 0, 0));
}
