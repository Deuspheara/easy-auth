use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn recovery_http_enforces_origin_queries_cookie_uniqueness_and_closed_bounded_bodies(
    pool: PgPool,
) {
    let r = Recovery::new(pool, true).await;
    let before = r.snapshot().await;
    for origin in [
        None,
        Some("null"),
        Some("https://other.example"),
        Some("https://app.example/"),
    ] {
        let response = r
            .app
            .clone()
            .oneshot(post(BIND, "{}", None, origin))
            .await
            .unwrap();
        rejected(response, StatusCode::FORBIDDEN, "origin_rejected").await;
    }
    let mut request = post(BIND, "{}", None, Some(ORIGIN));
    request
        .headers_mut()
        .append(header::ORIGIN, ORIGIN.parse().unwrap());
    rejected(
        r.app.clone().oneshot(request).await.unwrap(),
        StatusCode::FORBIDDEN,
        "origin_rejected",
    )
    .await;
    for path in [
        BIND,
        START,
        RESUME,
        STATUS,
        CANCEL,
        CANCEL_CODE,
        CANCEL_KEY,
        REPLACE,
        REGISTER,
        FINISH,
    ] {
        let response = r
            .app
            .clone()
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        rejected(
            send(
                &r.app,
                &format!("{path}?realm_id={}", r.f.auth.realm()),
                json!({}),
                Some(&r.cookie),
            )
            .await,
            StatusCode::BAD_REQUEST,
            "invalid_input",
        )
        .await;
    }
    for body in [
        json!({"realm_id":r.f.auth.realm()}),
        json!({"browser":"client-selects"}),
        json!({"session":"client-selects"}),
    ] {
        rejected(
            send(&r.app, BIND, body, Some(&r.cookie)).await,
            StatusCode::BAD_REQUEST,
            "invalid_body",
        )
        .await;
    }
    for cookie in [
        format!("{}; {}", r.cookie, r.cookie),
        format!("{RECOVERY_COOKIE}=bad"),
    ] {
        rejected(
            send(&r.app, BIND, json!({}), Some(&cookie)).await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    let response = r
        .app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(BIND)
                .header(header::ORIGIN, ORIGIN)
                .header(header::CONTENT_TYPE, "text/plain")
                .body(Body::from("{} "))
                .unwrap(),
        )
        .await
        .unwrap();
    rejected(response, StatusCode::UNSUPPORTED_MEDIA_TYPE, "invalid_body").await;
    for (path, size) in [(BIND, 8193), (REGISTER, 32769), (FINISH, 32769)] {
        let response = r
            .app
            .clone()
            .oneshot(post(path, &" ".repeat(size), Some(&r.cookie), Some(ORIGIN)))
            .await
            .unwrap();
        rejected(response, StatusCode::PAYLOAD_TOO_LARGE, "invalid_body").await;
    }
    assert!(
        r.snapshot().await == before,
        "boundary failures consume no claim or authorization state"
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn recovery_body_cannot_supply_realm_rp_session_browser_or_readiness_authority(pool: PgPool) {
    let r = Recovery::new(pool, true).await;
    let claim = r.start().await;
    for field in [
        "realm_id",
        "rp_id",
        "session",
        "browser",
        "ready",
        "not_before_ms",
        "notification_required",
    ] {
        let mut body = r.target(&claim);
        body[field] = "untrusted".into();
        rejected(
            send(&r.app, REPLACE, body, Some(&r.cookie)).await,
            StatusCode::BAD_REQUEST,
            "invalid_body",
        )
        .await;
    }
    for target in [
        json!({"account_id":Uuid::new_v4(),"claim_id":claim["claim_id"]}),
        json!({"account_id":r.f.owner,"claim_id":Uuid::new_v4()}),
    ] {
        rejected(
            send(&r.app, STATUS, target, Some(&r.cookie)).await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    let status = send(&r.app, STATUS, r.target(&claim), Some(&r.cookie)).await;
    assert_eq!(status.status(), StatusCode::OK);
    assert_eq!(json(status).await["ready"], false);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn bad_code_account_flood_cannot_block_bound_http_resume_or_fresh_key_cancellation(
    pool: PgPool,
) {
    let r = Recovery::new(pool, true).await;
    let claim = r.start().await;
    let wrong = Secret::generate().unwrap();
    for _ in 0..9 {
        rejected(
            send(
                &r.app,
                START,
                json!({"account_id":r.f.owner,"code":wrong.expose()}),
                Some(&r.cookie),
            )
            .await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    rejected(
        send(
            &r.app,
            START,
            json!({"account_id":r.f.owner,"code":wrong.expose()}),
            Some(&r.cookie),
        )
        .await,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
    )
    .await;
    let response = send(
        &r.app,
        RESUME,
        json!({"account_id":r.f.owner}),
        Some(&r.cookie),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(json(response).await, claim);
    let response = send(&r.app, CANCEL_KEY, json!({}), Some(&r.f.cookie())).await;
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    assert!(response.headers().get(header::SET_COOKIE).is_none());
}
