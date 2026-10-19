use super::*;

#[sqlx::test(migrations = "./migrations")]
async fn a_saved_code_reserves_one_claim_and_same_browser_retry_never_restarts_it(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let before: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_sessions WHERE realm_id=$1")
        .bind(f.f.realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    assert!(!claim.ready && claim.notification_required && claim.not_before_ms.is_none());
    let snapshot = f.snapshot().await;
    let retry = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    assert_eq!(retry.id, claim.id);
    assert_eq!(retry.expires_at_ms, claim.expires_at_ms);
    f.unchanged(snapshot).await;
    let other_browser = Secret::generate().unwrap();
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &other_browser, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    assert!(
        matches!(
            f.f.store
                .authenticate(f.f.realm, f.browser.verifier())
                .await,
            Err(Error::Unauthorized)
        ),
        "claim capability is not a session"
    );
    let after: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_sessions WHERE realm_id=$1")
        .bind(f.f.realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(before, after);
    let facts:(i64,i64,bool)=sqlx::query_as("SELECT (SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_started'),(SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1 AND kind='passkey_recovery_started'),(SELECT consumed_at IS NOT NULL FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2)")
        .bind(f.f.realm).bind(f.owner).fetch_one(&pool).await.unwrap();
    assert_eq!(facts, (1, 1, true));
}

#[sqlx::test(migrations = "./migrations")]
async fn offline_claim_reports_no_independent_alert_and_observes_a_full_delay(pool: PgPool) {
    let f = Claims::new(pool.clone(), true).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    assert!(!claim.ready && !claim.notification_required && claim.not_before_ms.is_some());
    assert!(
        f.f.store
            .claim_security_notice(f.f.realm)
            .await
            .unwrap()
            .is_none()
    );
    let durations:(i64,i64)=sqlx::query_as("SELECT extract(epoch FROM(not_before-created_at))::bigint,extract(epoch FROM(expires_at-created_at))::bigint FROM auth_passkey_recovery_claims WHERE realm_id=$1 AND user_id=$2")
        .bind(f.f.realm).bind(f.owner).fetch_one(&pool).await.unwrap();
    assert_eq!(durations, (86_400, 604_800));
    // Time-boundary storage fixture, not a protocol/session shortcut. Status is
    // metadata only; no endpoint or repository method can complete recovery yet.
    sqlx::query("UPDATE auth_passkey_recovery_claims SET created_at=created_at-interval '25 hours',not_before=not_before-interval '25 hours' WHERE realm_id=$1")
        .bind(f.f.realm).execute(&pool).await.unwrap();
    assert!(
        f.flow
            .status(f.owner, &f.browser, SOURCE, claim.id)
            .await
            .unwrap()
            .ready
    );
    assert!(matches!(
        f.f.store
            .authenticate(f.f.realm, f.browser.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    f.flow
        .cancel_with_key(&f.f.session, SOURCE, claim.id)
        .await
        .unwrap();
    assert!(matches!(
        f.flow.status(f.owner, &f.browser, SOURCE, claim.id).await,
        Err(Error::Unauthorized)
    ));
}

#[sqlx::test(migrations = "./migrations")]
async fn owner_realm_rp_browser_code_and_claim_id_bindings_fail_closed(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let peer = Claims::in_realm(pool.clone(), false, Some(f.f.realm)).await;
    let other = Claims::new(pool.clone(), false).await;
    let before = other.snapshot().await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    for mode in ["owner", "realm", "rp", "browser", "id"] {
        let mut request = f.request();
        let mut id = claim.id;
        match mode {
            "owner" => request.user_id = peer.owner,
            "realm" => request.realm = other.f.realm,
            "rp" => request.rp_id = "other.example.com".into(),
            "browser" => request.browser = Secret::generate().unwrap().verifier(),
            "id" => id = Uuid::new_v4(),
            _ => unreachable!(),
        }
        assert!(
            matches!(
                f.f.store.passkey_recovery_claim(&request, id).await,
                Err(Error::Unauthorized)
            ),
            "{mode} binding"
        );
    }
    let mut request = f.request();
    request.user_id = peer.owner;
    assert!(matches!(
        f.f.store
            .begin_passkey_recovery_claim(&request, Uuid::new_v4(), f.code.verifier())
            .await,
        Err(Error::Unauthorized)
    ));
    other.unchanged(before).await;
}

#[sqlx::test(migrations = "./migrations")]
async fn different_browser_race_has_one_winner_and_identical_retry_has_one_fact(pool: PgPool) {
    let f = Claims::new(pool.clone(), false).await;
    let other = Secret::generate().unwrap();
    let (a, b) = tokio::join!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE),
        f.flow.begin(f.owner, &f.code, &other, SOURCE)
    );
    assert!(
        matches!(
            (&a, &b),
            (Ok(_), Err(Error::Unauthorized)) | (Err(Error::Unauthorized), Ok(_))
        ),
        "infrastructure failures are not accepted race losers"
    );
    let f = Claims::new(pool.clone(), false).await;
    let (a, b) = tokio::join!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE),
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE)
    );
    assert_eq!(a.unwrap().id, b.unwrap().id);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_started'",
    )
    .bind(f.f.realm)
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "./migrations")]
async fn claim_expiry_prevents_resume_status_and_cancellation_without_reviving_the_code(
    pool: PgPool,
) {
    let f = Claims::new(pool.clone(), false).await;
    let claim = f
        .flow
        .begin(f.owner, &f.code, &f.browser, SOURCE)
        .await
        .unwrap();
    sqlx::query("UPDATE auth_passkey_recovery_claims SET created_at=created_at-interval '8 days',expires_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1")
        .bind(f.f.realm).execute(&pool).await.unwrap();
    let snapshot = f.snapshot().await;
    assert!(matches!(
        f.flow.begin(f.owner, &f.code, &f.browser, SOURCE).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.status(f.owner, &f.browser, SOURCE, claim.id).await,
        Err(Error::Unauthorized)
    ));
    assert!(matches!(
        f.flow.cancel(f.owner, &f.browser, SOURCE, claim.id).await,
        Err(Error::Unauthorized)
    ));
    f.unchanged(snapshot).await;
}
