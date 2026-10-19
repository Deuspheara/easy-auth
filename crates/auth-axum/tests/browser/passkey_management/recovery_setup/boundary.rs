use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn configuration_origin_cookie_body_media_and_query_boundary_is_closed(pool: PgPool) {
    let f = Fixture::new(pool.clone(), false).await;
    let app = app(&f, f.auth.clone());
    for path in [PREPARE, CONFIRM] {
        for origin in [None, Some("null"), Some("https://evil.example")] {
            rejected(
                app.clone()
                    .oneshot(post(path, "{}", Some(&f.cookie()), origin))
                    .await
                    .unwrap(),
                StatusCode::FORBIDDEN,
                "origin_rejected",
            )
            .await;
        }
        let mut duplicate = post(path, "{}", Some(&f.cookie()), Some(ORIGIN));
        duplicate
            .headers_mut()
            .append(header::ORIGIN, ORIGIN.parse().unwrap());
        rejected(
            app.clone().oneshot(duplicate).await.unwrap(),
            StatusCode::FORBIDDEN,
            "origin_rejected",
        )
        .await;
    }
    for cookie in [
        String::new(),
        "__Host-auth-session=invalid".into(),
        format!("{}; {}", f.cookie(), f.cookie()),
    ] {
        rejected(
            app.clone()
                .oneshot(post(PREPARE, "{}", Some(&cookie), Some(ORIGIN)))
                .await
                .unwrap(),
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    for (path, body) in [
        (PREPARE, json!({"owner":f.owner})),
        (
            CONFIRM,
            json!({"id":Uuid::new_v4(),"code":"invalid","rp_id":"untrusted"}),
        ),
        (CONFIRM, json!({"id":"invalid","code":"invalid"})),
    ] {
        rejected(
            send(&app, &f, path, &body).await,
            StatusCode::BAD_REQUEST,
            "invalid_body",
        )
        .await;
    }
    let duplicate = format!(
        "{{\"id\":\"{}\",\"id\":\"{}\",\"code\":\"invalid\"}}",
        Uuid::new_v4(),
        Uuid::new_v4()
    );
    rejected(
        app.clone()
            .oneshot(post(CONFIRM, &duplicate, Some(&f.cookie()), Some(ORIGIN)))
            .await
            .unwrap(),
        StatusCode::BAD_REQUEST,
        "invalid_body",
    )
    .await;
    for path in [PREPARE, CONFIRM] {
        rejected(
            send(&app, &f, &format!("{path}?realm_id=untrusted"), &json!({})).await,
            StatusCode::BAD_REQUEST,
            "invalid_input",
        )
        .await;
    }
    let mut wrong_media = post(PREPARE, "{}", Some(&f.cookie()), Some(ORIGIN));
    wrong_media
        .headers_mut()
        .insert(header::CONTENT_TYPE, "text/plain".parse().unwrap());
    rejected(
        app.clone().oneshot(wrong_media).await.unwrap(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
        "invalid_body",
    )
    .await;
    let oversized = format!("{{\"extra\":\"{}\"}}", "x".repeat(8192));
    rejected(
        app.clone()
            .oneshot(post(PREPARE, &oversized, Some(&f.cookie()), Some(ORIGIN)))
            .await
            .unwrap(),
        StatusCode::PAYLOAD_TOO_LARGE,
        "invalid_body",
    )
    .await;
    let get = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(PREPARE)
                .header(header::COOKIE, f.cookie())
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(get.status(), StatusCode::METHOD_NOT_ALLOWED);
    let count: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkey_recovery_setups WHERE realm_id=$1")
            .bind(f.auth.realm())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(count, 0);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn weak_or_stale_http_session_cannot_prepare_or_confirm_even_with_the_saved_code(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), false).await;
    let app = app(&f, f.auth.clone());
    let (id, code) = prepare(&app, &f).await;
    for method in ["email", "password", "legacy_unknown", "stale_passkey"] {
        sqlx::query("UPDATE auth_sessions SET authentication_method=$3,authenticated_at=CASE WHEN $4 THEN clock_timestamp()-interval '6 minutes' ELSE authenticated_at END WHERE realm_id=$1 AND token_hash=$2")
            .bind(f.auth.realm()).bind(f.session.verifier().as_slice()).bind(if method=="stale_passkey" {"passkey"} else {method}).bind(method=="stale_passkey").execute(&pool).await.unwrap();
        rejected(
            send(&app, &f, PREPARE, &json!({})).await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
        rejected(
            send(&app, &f, CONFIRM, &json!({"id":id,"code":code.expose()})).await,
            StatusCode::UNAUTHORIZED,
            "authentication_required",
        )
        .await;
    }
    let active: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkey_recovery_codes WHERE realm_id=$1")
            .bind(f.auth.realm())
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(active, 0);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn configuration_rejects_other_session_foreign_pending_and_wrong_code_without_consuming_valid_setup(
    pool: PgPool,
) {
    let f = Fixture::new(pool.clone(), false).await;
    let other = Fixture::new(pool.clone(), false).await;
    let app = app(&f, f.auth.clone());
    let (id, code) = prepare(&app, &f).await;
    let foreign_app = super::app(&other, other.auth.clone());
    let (foreign, foreign_code) = prepare(&foreign_app, &other).await;
    let (_, mut token) = f.add_key("Second key").await;
    let second = f.login(&mut token).await;
    let cookie = format!("__Host-auth-session={}", second.expose());
    rejected(
        app.clone()
            .oneshot(post(
                CONFIRM,
                &json!({"id":id,"code":code.expose()}).to_string(),
                Some(&cookie),
                Some(ORIGIN),
            ))
            .await
            .unwrap(),
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    rejected(
        send(
            &app,
            &f,
            CONFIRM,
            &json!({"id":foreign,"code":foreign_code.expose()}),
        )
        .await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    let wrong = Secret::generate().unwrap();
    rejected(
        send(&app, &f, CONFIRM, &json!({"id":id,"code":wrong.expose()})).await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    rejected(
        send(&app, &f, CONFIRM, &json!({"id":id,"code":"invalid"})).await,
        StatusCode::UNAUTHORIZED,
        "authentication_required",
    )
    .await;
    assert_eq!(
        send(&app, &f, CONFIRM, &json!({"id":id,"code":code.expose()}))
            .await
            .status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn exhausted_configuration_budget_returns_generic_rate_limit_without_exposing_another_code(
    pool: PgPool,
) {
    let f = Fixture::new(pool, false).await;
    let app = app(&f, f.auth.clone());
    for _ in 0..10 {
        prepare(&app, &f).await;
    }
    rejected(
        send(&app, &f, PREPARE, &json!({})).await,
        StatusCode::TOO_MANY_REQUESTS,
        "rate_limited",
    )
    .await;
}
