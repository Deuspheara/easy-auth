use super::*;
use serde_json::json;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn anonymous_start_enforces_origin_and_only_exposes_options_with_host_binding(pool: PgPool) {
    let (app, _, _) = app(pool.clone()).await;
    for origin in [None, Some("https://evil.example")] {
        let response = app
            .clone()
            .oneshot(post(START, r#"{"mode":"discoverable"}"#, None, origin))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }
    let response = app
        .clone()
        .oneshot(post(
            START,
            r#"{"mode":"discoverable"}"#,
            None,
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let binding = cookie(&response, "__Host-auth-passkey=");
    let set = response.headers()[header::SET_COOKIE].to_str().unwrap();
    for part in [
        "Secure",
        "HttpOnly",
        "Path=/",
        "SameSite=Lax",
        "Max-Age=120",
    ] {
        assert!(set.contains(part));
    }
    assert!(!set.contains("Domain="));
    let value: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 2);
    assert!(value.get("transaction_id").is_some());
    assert!(value["options"].get("mediation").is_none());
    assert_eq!(value["options"]["publicKey"]["allowCredentials"], json!([]));
    assert_eq!(
        value["options"]["publicKey"]["userVerification"],
        "required"
    );
    let duplicate = format!("{binding}; {binding}");
    let response = app
        .clone()
        .oneshot(post(
            START,
            r#"{"mode":"conditional"}"#,
            Some(&duplicate),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let malformed=json!({"transaction_id":value["transaction_id"],"credential":{"id":"AQ","rawId":"AQ","type":"public-key",
        "response":{"authenticatorData":"AA","clientDataJSON":"e30","signature":"AA","userHandle":null}}}).to_string();
    let response = app
        .oneshot(post(FINISH, &malformed, Some(&binding), Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    let error: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(error.as_object().unwrap().len(), 1);
    assert_eq!(error["code"], "authentication_required");
    let sessions: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_sessions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(sessions, 0);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn mode_contract_is_closed_bounded_and_disallows_email_credential_resolution(pool: PgPool) {
    let (app, _, _) = app(pool).await;
    for body in [
        r#"{}"#,
        r#"{"mode":"unknown"}"#,
        r#"{"mode":"discoverable","email":"alice@example.com"}"#,
        r#"{"mode":"conditional","account_id":"00000000-0000-0000-0000-000000000001"}"#,
        r#"{"mode":"account_bound","account_id":"00000000-0000-0000-0000-000000000001","email":"alice@example.com"}"#,
    ] {
        let response = app
            .clone()
            .oneshot(post(START, body, None, Some(ORIGIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
    let body = json!({"mode":"discoverable","padding":"x".repeat(33_000)}).to_string();
    let response = app
        .clone()
        .oneshot(post(START, &body, None, Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let response = app
        .oneshot(post(START, r#"{"mode":"conditional"}"#, None, Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let value: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(value["options"]["mediation"], "conditional");
}
