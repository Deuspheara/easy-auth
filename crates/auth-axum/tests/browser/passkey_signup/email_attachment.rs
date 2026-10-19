use super::*;
use auth_core::Repository;

const ATTACH_START: &str = "/v1/account/email/attachment/start";
const ATTACH_FINISH: &str = "/v1/account/email/attachment/finish";

async fn seed(pool: &PgPool, realm: Uuid) -> String {
    let user = Uuid::new_v4();
    // Storage/transport fixture; actual passkey possession is native-suite evidence.
    sqlx::query("INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy) VALUES ($1,$2,NULL,NULL,'Person','passkey_required')")
        .bind(realm).bind(user).execute(pool).await.unwrap();
    let secret = Secret::generate().unwrap();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'passkey')")
        .bind(realm).bind(Uuid::new_v4()).bind(user).bind(secret.verifier().as_slice()).execute(pool).await.unwrap();
    format!("__Host-auth-session={}", secret.expose())
}

async fn profile(app: &Router, current: &str) -> axum::response::Response {
    app.clone()
        .oneshot(
            Request::builder()
                .uri("/v1/session")
                .header(header::COOKIE, current)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap()
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn verified_contact_rotates_cookie_preserves_identity_and_never_enables_weaker_login(
    pool: PgPool,
) {
    let (app, auth, _, mail) = app_with_mail(pool.clone()).await;
    let current = seed(&pool, auth.realm()).await;
    let before = json(profile(&app, &current).await).await;
    let response = app
        .clone()
        .oneshot(post(
            ATTACH_START,
            r#"{"email":"CONTACT@EXAMPLE.COM"}"#,
            Some(&current),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let binding = cookie(&response, "__Host-auth-attach=");
    let full = response.headers()[header::SET_COOKIE].to_str().unwrap();
    for flag in ["Secure", "HttpOnly", "SameSite=Lax", "Max-Age=300"] {
        assert!(full.contains(flag));
    }
    assert_eq!(
        json(response).await,
        serde_json::json!({"status":"accepted"})
    );
    let (target, proof) = mail.attachments.lock().unwrap().last().unwrap().clone();
    assert_eq!(target, "contact@example.com");
    let both = format!("{current}; {binding}");
    let page = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/email-attach")
                .header(header::COOKIE, &both)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(page.status(), StatusCode::OK);
    assert_eq!(
        json(profile(&app, &current).await).await["email"],
        serde_json::Value::Null
    );
    let body = serde_json::json!({"token":proof}).to_string();
    assert_eq!(
        app.clone()
            .oneshot(post(ATTACH_FINISH, &body, Some(&current), Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    let response = app
        .clone()
        .oneshot(post(ATTACH_FINISH, &body, Some(&both), Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    let replacement = cookie(&response, "__Host-auth-session=");
    assert!(replacement != current, "session must rotate");
    assert_eq!(
        profile(&app, &current).await.status(),
        StatusCode::UNAUTHORIZED
    );
    let user = json(profile(&app, &replacement).await).await;
    assert_eq!(user["id"], before["id"]);
    assert_eq!(user["email"], "contact@example.com");
    let denied = app
        .clone()
        .oneshot(post(
            "/v1/password/enroll",
            r#"{"password":"a sufficiently long example password"}"#,
            Some(&replacement),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        app.oneshot(post(ATTACH_FINISH, &body, Some(&both), Some(ORIGIN)))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn delivery_failure_has_no_binding_or_identity_mutation_and_retry_uses_a_new_proof(
    pool: PgPool,
) {
    let (app, auth, _, mail) = app_with_mail(pool.clone()).await;
    let current = seed(&pool, auth.realm()).await;
    *mail.fail_attachments.lock().unwrap() = true;
    let response = app
        .clone()
        .oneshot(post(
            ATTACH_START,
            r#"{"email":"contact@example.com"}"#,
            Some(&current),
            Some(ORIGIN),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert!(mail.attachments.lock().unwrap().is_empty());
    assert_eq!(
        json(profile(&app, &current).await).await["email"],
        serde_json::Value::Null
    );
    *mail.fail_attachments.lock().unwrap() = false;
    assert_eq!(
        app.clone()
            .oneshot(post(
                ATTACH_START,
                r#"{"email":"contact@example.com"}"#,
                Some(&current),
                Some(ORIGIN)
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::ACCEPTED
    );
    assert_eq!(mail.attachments.lock().unwrap().len(), 1);
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_email_attachments")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(pending, 1);
}

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn attachment_is_opt_in_bound_strict_and_does_not_enumerate_owned_targets(pool: PgPool) {
    let (app, auth, store, mail) = app_with_mail(pool.clone()).await;
    let current = seed(&pool, auth.realm()).await;
    let normal = easy_auth_axum::router(auth.clone(), BrowserConfig::new(ORIGIN, false).unwrap());
    assert_eq!(
        normal
            .oneshot(post(
                ATTACH_START,
                r#"{"email":"contact@example.com"}"#,
                Some(&current),
                Some(ORIGIN)
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::NOT_FOUND
    );
    for (body, origin, cookie, status) in [
        (
            r#"{"email":"contact@example.com"}"#,
            None,
            Some(current.as_str()),
            StatusCode::FORBIDDEN,
        ),
        (
            r#"{"email":"contact@example.com"}"#,
            Some(ORIGIN),
            None,
            StatusCode::UNAUTHORIZED,
        ),
        (
            r#"{"email":"contact@example.com","user_id":"untrusted"}"#,
            Some(ORIGIN),
            Some(current.as_str()),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(post(ATTACH_START, body, cookie, origin))
                .await
                .unwrap()
                .status(),
            status
        );
    }
    let secret = Secret::generate().unwrap();
    store
        .begin_email(auth.realm(), "owned@example.com", [1; 32], [2; 32], [3; 32])
        .await
        .unwrap();
    store
        .finish_email(auth.realm(), [1; 32], [2; 32], secret.verifier())
        .await
        .unwrap();
    for email in ["owned@example.com", "available@example.com"] {
        let response = app
            .clone()
            .oneshot(post(
                ATTACH_START,
                &serde_json::json!({"email":email}).to_string(),
                Some(&current),
                Some(ORIGIN),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        assert_eq!(
            json(response).await,
            serde_json::json!({"status":"accepted"})
        );
    }
    assert_eq!(mail.attachments.lock().unwrap().len(), 2);
}
