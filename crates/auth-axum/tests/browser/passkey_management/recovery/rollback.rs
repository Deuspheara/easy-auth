use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn failed_claim_or_completion_persistence_returns_no_success_cookie_and_remains_retryable(
    pool: PgPool,
) {
    for stage in ["claim", "completion"] {
        let r = Recovery::new(pool.clone(), false).await;
        let claim = if stage == "completion" {
            let claim = r.start().await;
            r.mature(&claim).await;
            Some(claim)
        } else {
            None
        };
        let pending = if let Some(claim) = &claim {
            Some(r.assertion(claim).await)
        } else {
            None
        };
        let kind = if stage == "claim" {
            "passkey_recovery_started"
        } else {
            "passkey_recovered"
        };
        sqlx::raw_sql(&format!("CREATE OR REPLACE FUNCTION reject_http_recovery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='{kind}' THEN RAISE EXCEPTION 'test infrastructure: deliberate recovery audit failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER reject_http_recovery BEFORE INSERT ON auth_audit FOR EACH ROW EXECUTE FUNCTION reject_http_recovery();")).execute(&pool).await.unwrap();
        let before = r.snapshot().await;
        let (path, body) = if let (Some(claim), Some((id, signed, _))) = (&claim, &pending) {
            (FINISH, r.finish_body(claim, *id, signed))
        } else {
            (
                START,
                json!({"account_id":r.f.owner,"code":r.code.expose()}),
            )
        };
        rejected(
            send(&r.app, path, body.clone(), Some(&r.cookie)).await,
            StatusCode::SERVICE_UNAVAILABLE,
            "temporarily_unavailable",
        )
        .await;
        assert!(
            r.snapshot().await == before,
            "storage failure must roll back all durable authority state"
        );
        sqlx::query("DROP TRIGGER reject_http_recovery ON auth_audit")
            .execute(&pool)
            .await
            .unwrap();
        let response = send(&r.app, path, body, Some(&r.cookie)).await;
        assert_eq!(
            response.status(),
            if stage == "claim" {
                StatusCode::OK
            } else {
                StatusCode::NO_CONTENT
            }
        );
        assert_eq!(
            response.headers().get(header::SET_COOKIE).is_some(),
            stage == "completion"
        );
    }
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn bad_assertion_or_cancelled_preverified_http_ceremony_cannot_issue_session(pool: PgPool) {
    let r = Recovery::new(pool, true).await;
    let claim = r.start().await;
    r.mature(&claim).await;
    let (id, signed, _) = r.assertion(&claim).await;
    let mut bad = r.finish_body(&claim, id, &signed);
    bad["credential"]["response"]["clientDataJSON"] = "e30".into();
    let before = r.snapshot().await;
    rejected(
        send(&r.app, FINISH, bad, Some(&r.cookie)).await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    assert!(r.snapshot().await == before);
    let response = send(&r.app, CANCEL, r.target(&claim), Some(&r.cookie)).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let before = r.snapshot().await;
    rejected(
        send(
            &r.app,
            FINISH,
            r.finish_body(&claim, id, &signed),
            Some(&r.cookie),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    assert!(r.snapshot().await == before);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn failed_notification_delivery_never_sets_http_readiness_or_creates_fallback_authority(
    pool: PgPool,
) {
    let r = Recovery::new(pool.clone(), false).await;
    let claim = r.start().await;
    let mail = Arc::new(Mail::default());
    *mail.fail_notices.lock().unwrap() = true;
    let auth = Auth::new(r.f.auth.realm(), r.f.store.clone(), mail.clone());
    assert!(matches!(
        auth.deliver_security_notice().await,
        Err(auth_core::Error::Unavailable)
    ));
    let response = send(&r.app, STATUS, r.target(&claim), Some(&r.cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let status = json(response).await;
    assert!(status["not_before_ms"].is_null());
    assert_eq!(status["ready"], false);
    rejected(
        send(&r.app, REPLACE, r.target(&claim), Some(&r.cookie)).await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    *mail.fail_notices.lock().unwrap() = false;
    sqlx::query("UPDATE auth_security_notifications SET next_attempt_at=clock_timestamp()-interval '1 second' WHERE realm_id=$1").bind(r.f.auth.realm()).execute(&pool).await.unwrap();
    assert!(auth.deliver_security_notice().await.unwrap());
    let response = send(&r.app, STATUS, r.target(&claim), Some(&r.cookie)).await;
    assert_eq!(response.status(), StatusCode::OK);
    let status = json(response).await;
    assert!(status["not_before_ms"].is_i64());
    assert_eq!(status["ready"], false);
}
