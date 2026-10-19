use super::*;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn signup_requires_exact_origin_anonymous_cookies_and_closed_bounded_input(pool: PgPool) {
    let (app, _, _) = app(pool.clone()).await;
    for origin in [None, Some("https://other.example"), Some("null")] {
        let response = app
            .clone()
            .oneshot(post(START, r#"{"display_name":"Person"}"#, None, origin))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let session = Secret::generate().unwrap();
    for cookie in [
        format!("__Host-auth-session={}", session.expose()),
        "__Host-auth-session=invalid".to_owned(),
        format!(
            "__Host-auth-session={}; __Host-auth-session={}",
            session.expose(),
            session.expose()
        ),
    ] {
        for (path, body) in [
            (START, serde_json::json!({"display_name":"Person"})),
            (
                REGISTRATION,
                serde_json::json!({"transaction_id":Uuid::new_v4(),"credential":registration()}),
            ),
            (
                FINISH,
                serde_json::json!({"transaction_id":Uuid::new_v4(),"credential":assertion()}),
            ),
        ] {
            let response = app
                .clone()
                .oneshot(post(path, &body.to_string(), Some(&cookie), Some(ORIGIN)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
        }
    }
    for body in [
        r#"{"display_name":"Person","email":"untrusted@example.test"}"#,
        r#"{"display_name":"Person","user_id":"untrusted"}"#,
        r#"{"display_name":"Person","rp_id":"untrusted"}"#,
        r#"{"display_name":"Person","discoverable":false}"#,
        r#"{"display_name":"Person","display_name":"Other"}"#,
    ] {
        assert_eq!(
            app.clone()
                .oneshot(post(START, body, None, Some(ORIGIN)))
                .await
                .unwrap()
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let medium = serde_json::json!({"display_name":"x".repeat(9000)}).to_string();
    assert_eq!(
        app.clone()
            .oneshot(post(START, &medium, None, Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST,
        "signup routes retain their 32 KiB transport bound and reject the label semantically"
    );
    let oversized = serde_json::json!({"display_name":"x".repeat(33000)}).to_string();
    assert_eq!(
        app.clone()
            .oneshot(post(START, &oversized, None, Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey_signups")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 0);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn pending_signup_sets_only_binding_and_bad_stage_proofs_cannot_mint_identity(pool: PgPool) {
    let (app, _, _) = app(pool.clone()).await;
    let response = app
        .clone()
        .oneshot(post(
            START,
            r#"{"display_name":"Only a display label"}"#,
            None,
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .count(),
        1
    );
    let binding = cookie(&response, "__Host-auth-passkey=");
    let full_cookie = response.headers()[header::SET_COOKIE].to_str().unwrap();
    for flag in [
        "HttpOnly",
        "Secure",
        "SameSite=Lax",
        "Path=/",
        "Max-Age=120",
    ] {
        assert!(full_cookie.contains(flag));
    }
    let pending = json(response).await;
    assert_eq!(
        pending["options"]["publicKey"]["authenticatorSelection"]["residentKey"],
        "required"
    );
    assert_eq!(
        pending["options"]["publicKey"]["authenticatorSelection"]["userVerification"],
        "required"
    );
    assert!(pending.get("state").is_none());
    for (path, credential) in [(REGISTRATION, registration()), (FINISH, assertion())] {
        let body =
            serde_json::json!({"transaction_id":pending["transaction_id"],"credential":credential})
                .to_string();
        for cookie in [None, Some(binding.as_str())] {
            let response = app
                .clone()
                .oneshot(post(path, &body, cookie, Some(ORIGIN)))
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
            assert!(!response.headers().contains_key(header::SET_COOKIE));
        }
    }
    let counts: (i64,i64,i64,i64) = sqlx::query_as("SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_passkeys),(SELECT count(*) FROM auth_sessions),(SELECT count(*) FROM auth_audit)")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(counts, (0, 0, 0, 0));
    let stage: String = sqlx::query_scalar("SELECT stage FROM auth_passkey_signups")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(stage, "registration");
}
