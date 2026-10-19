use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn recovery_binding_is_independent_idempotent_and_precedes_code_consumption(pool: PgPool) {
    let r = Recovery::new(pool, true).await;
    let before = r.snapshot().await;
    rejected(
        send(
            &r.app,
            START,
            json!({"account_id":r.f.owner,"code":r.code.expose()}),
            None,
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    let response = send(&r.app, BIND, json!({}), Some(&r.cookie)).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with(&r.cookie));
    for flag in [
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        "Secure",
        "Max-Age=604800",
    ] {
        assert!(cookie.contains(flag));
    }
    assert!(
        r.snapshot().await == before,
        "binding creates no database state and missing binding cannot consume a code"
    );
    let claim = r.start().await;
    let resumed = send(
        &r.app,
        RESUME,
        json!({"account_id":r.f.owner}),
        Some(&r.cookie),
    )
    .await;
    assert_eq!(resumed.status(), StatusCode::OK);
    assert!(resumed.headers().get(header::SET_COOKIE).is_none());
    assert_eq!(
        json(resumed).await,
        claim,
        "lost start response resumes identical original claim"
    );
    let retried = r.start().await;
    assert_eq!(retried, claim);
    let count: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_started'",
    )
    .bind(r.f.auth.realm())
    .fetch_one(&r.f.pool)
    .await
    .unwrap();
    assert_eq!(count, 1);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn recovery_never_selects_or_overwrites_an_existing_session_or_other_purpose_cookie(
    pool: PgPool,
) {
    let r = Recovery::new(pool, true).await;
    for cookie in [
        r.f.cookie(),
        r.f.mailbox_cookie.clone(),
        format!("{}; {}", r.cookie, r.f.cookie()),
        format!(
            "__Host-auth-session={}; __Host-auth-session={}",
            r.f.session.expose(),
            r.f.session.expose()
        ),
        format!("__Host-auth-passkey={}", r.f.browser.expose()),
    ] {
        rejected(
            send(
                &r.app,
                START,
                json!({"account_id":r.f.owner,"code":r.code.expose()}),
                Some(&cookie),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    let claim = r.start().await;
    let other = Secret::generate().unwrap();
    let other_cookie = format!("{RECOVERY_COOKIE}={}", other.expose());
    for path in [RESUME, STATUS, CANCEL, REPLACE] {
        let body = if path == RESUME {
            json!({"account_id":r.f.owner})
        } else {
            r.target(&claim)
        };
        rejected(
            send(&r.app, path, body, Some(&other_cookie)).await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    rejected(
        send(
            &r.app,
            START,
            json!({"account_id":r.f.owner,"code":r.code.expose()}),
            Some(&other_cookie),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    let status = send(&r.app, STATUS, r.target(&claim), Some(&r.cookie)).await;
    assert_eq!(status.status(), StatusCode::OK);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn loopback_recovery_binding_uses_only_explicit_development_cookie_policy(pool: PgPool) {
    let mut f = Fixture::new(pool, true).await;
    let origin = "http://localhost:58417";
    f.service = Arc::new(PasskeyService::for_local_development(origin, "Example").unwrap());
    f.enrollment = Arc::new(PasskeyEnrollment::new(
        f.auth.realm(),
        f.service.clone(),
        f.store.clone(),
    ));
    f.sign_in = Arc::new(PasskeySignIn::new(
        f.auth.realm(),
        f.service.clone(),
        f.store.clone(),
    ));
    let app = experimental_passkey_recovery_router(
        f.auth.clone(),
        BrowserConfig::new(origin, true).unwrap(),
        services(&f),
    )
    .unwrap();
    let response = app
        .oneshot(post(BIND, "{}", None, Some(origin)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    assert!(cookie.starts_with("auth-passkey-recovery="));
    assert!(!cookie.contains("Secure"));
    assert!(!cookie.contains("Domain="));
    assert!(
        cookie.contains("HttpOnly") && cookie.contains("SameSite=Lax") && cookie.contains("Path=/")
    );
}
