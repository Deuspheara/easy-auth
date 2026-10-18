use async_trait::async_trait;
use auth_core::{Auth, EmailDelivery, PasswordService, Secret};
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use easy_auth_axum::BrowserConfig;
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;
#[derive(Default)]
struct Mail(
    Mutex<Vec<String>>,
    Mutex<Vec<String>>,
    Mutex<usize>,
    Mutex<bool>,
    Mutex<Vec<(String, String)>>,
    Mutex<Vec<String>>,
);
#[async_trait]
impl EmailDelivery for Mail {
    async fn email_change(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        self.4
            .lock()
            .unwrap()
            .push((email.to_owned(), token.expose().to_owned()));
        Ok(())
    }
    async fn account_deletion(&self, _email: &str, token: &Secret) -> auth_core::Result<()> {
        self.5.lock().unwrap().push(token.expose().to_owned());
        Ok(())
    }
    async fn email_changed(&self, _email: &str) -> auth_core::Result<()> {
        *self.2.lock().unwrap() += 1;
        Ok(())
    }
    async fn account_deleted(&self, _email: &str) -> auth_core::Result<()> {
        *self.2.lock().unwrap() += 1;
        Ok(())
    }
    async fn password_reset(&self, _email: &str, token: &Secret) -> auth_core::Result<()> {
        self.1.lock().unwrap().push(token.expose().to_owned());
        Ok(())
    }
    async fn password_changed(&self, _email: &str) -> auth_core::Result<()> {
        if *self.3.lock().unwrap() {
            return Err(auth_core::Error::Unavailable);
        }
        *self.2.lock().unwrap() += 1;
        Ok(())
    }

    async fn sign_in(&self, _email: &str, token: &Secret) -> auth_core::Result<()> {
        self.0.lock().unwrap().push(token.expose().to_owned());
        Ok(())
    }
}
async fn app(pool: PgPool) -> (Router, Arc<Mail>) {
    let store = Postgres::new(pool);
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let mail = Arc::new(Mail::default());
    (
        easy_auth_axum::router(
            Auth::new(realm, Arc::new(store), mail.clone()).with_passwords(Arc::new(
                PasswordService::new("a compromised example password").unwrap(),
            )),
            BrowserConfig::new("https://app.example", false).unwrap(),
        ),
        mail,
    )
}
fn post(path: &str, body: &str, cookie: Option<&str>, origin: Option<&str>) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(cookie) = cookie {
        req = req.header(header::COOKIE, cookie);
    }
    if let Some(origin) = origin {
        req = req.header(header::ORIGIN, origin);
    }
    req.body(Body::from(body.to_owned())).unwrap()
}
fn cookie(response: &axum::response::Response, name: &str) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(name))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}
#[sqlx::test]
async fn browser_email_session_logout_end_to_end(pool: PgPool) {
    let (app, mail) = app(pool).await;
    let start = app
        .clone()
        .oneshot(post(
            "/v1/email/start",
            r#"{"email":"alice@example.com"}"#,
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::ACCEPTED);
    let browser = cookie(&start, "__Host-auth-browser=");
    assert!(
        start.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Secure")
    );
    let token = mail.0.lock().unwrap()[0].clone();
    let body = serde_json::json!({"token":token}).to_string();
    let invalid = app
        .clone()
        .oneshot(post(
            "/v1/email/finish",
            &body,
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(invalid.status(), StatusCode::UNAUTHORIZED);
    let finished = app
        .clone()
        .oneshot(post(
            "/v1/email/finish",
            &body,
            Some(&browser),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(finished.status(), StatusCode::NO_CONTENT);
    let session = cookie(&finished, "__Host-auth-session=");
    let replay = app
        .clone()
        .oneshot(post(
            "/v1/email/finish",
            &body,
            Some(&browser),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(replay.status(), StatusCode::UNAUTHORIZED);
    let request = || {
        Request::builder()
            .uri("/v1/session")
            .header(header::COOKIE, &session)
            .body(Body::empty())
            .unwrap()
    };
    let protected = app.clone().oneshot(request()).await.unwrap();
    assert_eq!(protected.status(), StatusCode::OK);
    assert_eq!(protected.headers()[header::CACHE_CONTROL], "no-store");
    let user: serde_json::Value =
        serde_json::from_slice(&protected.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(user["email"], "alice@example.com");
    assert!(user.get("token").is_none());
    let logout = app
        .clone()
        .oneshot(post(
            "/v1/logout",
            "{}",
            Some(&session),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    assert!(
        logout.headers()[header::SET_COOKIE]
            .to_str()
            .unwrap()
            .contains("Max-Age=0")
    );
    assert_eq!(
        app.oneshot(request()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
#[sqlx::test]
async fn reject_origin_body_and_cookie_attacks(pool: PgPool) {
    let (app, mail) = app(pool).await;
    for origin in [
        None,
        Some("null"),
        Some("https://evil.example"),
        Some("https://app.example.evil"),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(post(
                    "/v1/email/start",
                    r#"{"email":"a@example.com"}"#,
                    None,
                    origin
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }
    assert!(mail.0.lock().unwrap().is_empty());
    let big = serde_json::json!({"email":"a".repeat(9000)}).to_string();
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/email/start",
                &big,
                None,
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let token = Secret::generate().unwrap();
    let cookie = format!(
        "__Host-auth-session={}; __Host-auth-session={}",
        token.expose(),
        token.expose()
    );
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/session")
                .header(header::COOKIE, cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/v1/email/finish?token=ignored")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[sqlx::test]
async fn published_contract_matches_live_spec_and_rejections_are_redacted(pool: PgPool) {
    let (app, _) = app(pool).await;
    let spec = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(spec.status(), StatusCode::OK);
    let live: serde_json::Value =
        serde_json::from_slice(&spec.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let published: serde_json::Value =
        serde_json::from_str(include_str!("../../../docs/openapi.json")).unwrap();
    assert_eq!(
        live, published,
        "regenerate docs/openapi.json when changing the contract"
    );
    assert_eq!(
        live["paths"]["/v1/email/start"]["post"]["responses"]["202"]["description"],
        "Generic response; sets HttpOnly browser binding"
    );
    let malformed = app
        .oneshot(post(
            "/v1/email/finish",
            r#"{"token":123,"secret":"must-not-echo"}"#,
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
    let body = malformed.into_body().collect().await.unwrap().to_bytes();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).unwrap(),
        serde_json::json!({"code":"invalid_body"})
    );
}

async fn sign_in(app: &Router, mail: &Mail, email: &str) -> String {
    let response = app
        .clone()
        .oneshot(post(
            "/v1/email/start",
            &serde_json::json!({"email":email}).to_string(),
            None,
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::ACCEPTED);
    let browser = cookie(&response, "__Host-auth-browser=");
    let token = mail.0.lock().unwrap().last().unwrap().clone();
    let response = app
        .clone()
        .oneshot(post(
            "/v1/email/finish",
            &serde_json::json!({"token":token}).to_string(),
            Some(&browser),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::NO_CONTENT);
    cookie(&response, "__Host-auth-session=")
}
#[sqlx::test]
async fn password_enrollment_and_login_use_shared_sessions(pool: PgPool) {
    let (app, mail) = app(pool.clone()).await;
    let previous = sign_in(&app, &mail, "alice@example.com").await;
    let good = serde_json::json!({"password":"correct horse sample password"}).to_string();
    let blocked = serde_json::json!({"password":"a compromised example password"}).to_string();
    for (body, session, origin, status) in [
        (
            &good,
            None,
            Some("https://app.example"),
            StatusCode::UNAUTHORIZED,
        ),
        (&good, Some(previous.as_str()), None, StatusCode::FORBIDDEN),
        (
            &blocked,
            Some(previous.as_str()),
            Some("https://app.example"),
            StatusCode::BAD_REQUEST,
        ),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(post("/v1/password/enroll", body, session, origin))
                .await
                .unwrap()
                .status(),
            status
        );
    }
    let enrolled = app
        .clone()
        .oneshot(post(
            "/v1/password/enroll",
            &good,
            Some(&previous),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(enrolled.status(), StatusCode::NO_CONTENT);
    let replacement = cookie(&enrolled, "__Host-auth-session=");
    assert_ne!(replacement, previous);
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header(header::COOKIE, &previous)
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/password/enroll",
                &good,
                Some(&replacement),
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    // Unknown user, email-only user and wrong password share status/body; no credential detail is reflected.
    sign_in(&app, &mail, "email-only@example.com").await;
    let mut errors = Vec::new();
    for email in [
        "missing@example.com",
        "alice@example.com",
        "email-only@example.com",
    ] {
        let body = serde_json::json!({"email":email,"password":"an incorrect example password"})
            .to_string();
        let rejected = app
            .clone()
            .oneshot(post(
                "/v1/password/login",
                &body,
                None,
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(rejected.status(), StatusCode::UNAUTHORIZED);
        errors.push(rejected.into_body().collect().await.unwrap().to_bytes());
    }
    assert_eq!(errors[0], errors[1]);
    assert_eq!(errors[0], errors[2]);
    let login =
        serde_json::json!({"email":"ALICE@example.com","password":"correct horse sample password"})
            .to_string();
    let logged_in = app
        .clone()
        .oneshot(post(
            "/v1/password/login",
            &login,
            Some(&replacement),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(logged_in.status(), StatusCode::NO_CONTENT);
    let session = cookie(&logged_in, "__Host-auth-session=");
    assert_ne!(session, replacement);
    let user = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/session")
                .header(header::COOKIE, &session)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(user.status(), StatusCode::OK);
    assert_eq!(user.headers()[header::CACHE_CONTROL], "no-store");
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM auth_password_credentials")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(hash.starts_with("$argon2id$v=19$m=65536,t=3,p=1$"));
    assert!(!hash.contains("correct horse"));
    assert_eq!(
        app.oneshot(post(
            "/v1/logout",
            "{}",
            Some(&session),
            Some("https://app.example")
        ))
        .await
        .unwrap()
        .status(),
        StatusCode::NO_CONTENT
    );
}

#[sqlx::test]
async fn password_feature_without_corpus_is_unavailable(pool: PgPool) {
    let store = Postgres::new(pool);
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let app = easy_auth_axum::router(
        Auth::new(realm, Arc::new(store), Arc::new(Mail::default())),
        BrowserConfig::new("https://app.example", false).unwrap(),
    );
    let secret = Secret::generate().unwrap();
    let cookie = format!("__Host-auth-session={}", secret.expose());
    for (path, body) in [
        (
            "/v1/password/enroll",
            r#"{"password":"synthetic example password"}"#,
        ),
        (
            "/v1/password/login",
            r#"{"email":"nobody@example.com","password":"synthetic example password"}"#,
        ),
    ] {
        let response = app
            .clone()
            .oneshot(post(path, body, Some(&cookie), Some("https://app.example")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }
}

#[sqlx::test]
async fn recovery_http_proofs_sessions_and_retryable_notification(pool: PgPool) {
    let store = Postgres::new(pool.clone());
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let mail = Arc::new(Mail::default());
    let auth = Auth::new(realm, Arc::new(store), mail.clone()).with_passwords(Arc::new(
        PasswordService::new("a compromised example password").unwrap(),
    ));
    let app = easy_auth_axum::router(
        auth.clone(),
        BrowserConfig::new("https://app.example", false).unwrap(),
    );
    let initial = sign_in(&app, &mail, "alice@example.com").await;
    let old = "old synthetic password phrase";
    let new = "new synthetic password phrase";
    let enrolled = app
        .clone()
        .oneshot(post(
            "/v1/password/enroll",
            &serde_json::json!({"password":old}).to_string(),
            Some(&initial),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(enrolled.status(), StatusCode::NO_CONTENT);
    let previous = cookie(&enrolled, "__Host-auth-session=");
    sign_in(&app, &mail, "email-only@example.com").await;
    let mut responses = Vec::new();
    let mut binding = String::new();
    for email in [
        "alice@example.com",
        "unknown@example.com",
        "email-only@example.com",
    ] {
        let response = app
            .clone()
            .oneshot(post(
                "/v1/password/reset/start",
                &serde_json::json!({"email":email}).to_string(),
                None,
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let current = cookie(&response, "__Host-auth-reset=");
        assert!(
            response.headers()[header::SET_COOKIE]
                .to_str()
                .unwrap()
                .contains("Secure")
        );
        if binding.is_empty() {
            binding = current;
        }
        responses.push(response.into_body().collect().await.unwrap().to_bytes());
    }
    assert_eq!(responses[0], responses[1]);
    assert_eq!(responses[0], responses[2]);
    assert_eq!(
        mail.1.lock().unwrap().len(),
        3,
        "same mail path, independent of account status"
    );
    let token = mail.1.lock().unwrap()[0].clone();
    let body = serde_json::json!({"token":token,"password":new}).to_string();
    for (cookie, origin, status) in [
        (None, Some("https://app.example"), StatusCode::UNAUTHORIZED),
        (Some(binding.as_str()), None, StatusCode::FORBIDDEN),
    ] {
        assert_eq!(
            app.clone()
                .oneshot(post("/v1/password/reset/finish", &body, cookie, origin))
                .await
                .unwrap()
                .status(),
            status
        );
    }
    let invalid =
        serde_json::json!({"token":token,"password":"a compromised example password"}).to_string();
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/password/reset/finish",
                &invalid,
                Some(&binding),
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    *mail.3.lock().unwrap() = true;
    let completed = app
        .clone()
        .oneshot(post(
            "/v1/password/reset/finish",
            &body,
            Some(&binding),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::NO_CONTENT);
    assert!(
        completed
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|h| h.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/password/reset/finish",
                &body,
                Some(&binding),
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header(header::COOKIE, &previous)
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    for (password, expected) in [
        (old, StatusCode::UNAUTHORIZED),
        (new, StatusCode::NO_CONTENT),
    ] {
        let response = app
            .clone()
            .oneshot(post(
                "/v1/password/login",
                &serde_json::json!({"email":"alice@example.com","password":password}).to_string(),
                None,
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
    }
    assert!(auth.deliver_security_notice().await.is_err());
    sqlx::query("UPDATE auth_security_notifications SET next_attempt_at=clock_timestamp()-interval '1 second'").execute(&pool).await.unwrap();
    *mail.3.lock().unwrap() = false;
    assert!(auth.deliver_security_notice().await.unwrap());
    assert!(!auth.deliver_security_notice().await.unwrap());
    assert_eq!(*mail.2.lock().unwrap(), 1);
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/v1/password/reset/finish?token=ignored")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::METHOD_NOT_ALLOWED
    );
}

#[sqlx::test]
async fn account_lifecycle_http_with_email_only_account(pool: PgPool) {
    let store = Postgres::new(pool.clone());
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let mail = Arc::new(Mail::default());
    let auth = Auth::new(realm, Arc::new(store), mail.clone());
    let app = easy_auth_axum::router(
        auth.clone(),
        BrowserConfig::new("https://app.example", false).unwrap(),
    );
    let current = sign_in(&app, &mail, "alice@example.com").await;
    let old_user: Uuid = sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    let change = r#"{"email":"new@example.com"}"#;
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/account/email/start",
                change,
                Some(&current),
                None
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::FORBIDDEN
    );
    let started = app
        .clone()
        .oneshot(post(
            "/v1/account/email/start",
            change,
            Some(&current),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::ACCEPTED);
    let binding = cookie(&started, "__Host-auth-email-change=");
    let cookies = format!("{current}; {binding}");
    let messages = mail.4.lock().unwrap().clone();
    assert_eq!(messages.len(), 2);
    assert_eq!(messages[0].0, "alice@example.com");
    assert_eq!(messages[1].0, "new@example.com");
    for (i, (_, token)) in messages.iter().enumerate() {
        let response = app
            .clone()
            .oneshot(post(
                "/v1/account/email/confirm",
                &serde_json::json!({"token":token}).to_string(),
                Some(&cookies),
                Some("https://app.example"),
            ))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if i == 0 {
                StatusCode::ACCEPTED
            } else {
                StatusCode::NO_CONTENT
            }
        );
    }
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/v1/session")
                    .header(header::COOKIE, &current)
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert!(auth.deliver_security_notice().await.unwrap());
    let current = sign_in(&app, &mail, "new@example.com").await;
    let new_user: Uuid = sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(old_user, new_user);
    assert_eq!(
        app.clone()
            .oneshot(post(
                "/v1/account/delete/start",
                r#"{"confirmation":"wrong"}"#,
                Some(&current),
                Some("https://app.example")
            ))
            .await
            .unwrap()
            .status(),
        StatusCode::BAD_REQUEST
    );
    let started = app
        .clone()
        .oneshot(post(
            "/v1/account/delete/start",
            r#"{"confirmation":"delete my account"}"#,
            Some(&current),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(started.status(), StatusCode::ACCEPTED);
    let binding = cookie(&started, "__Host-auth-delete=");
    let cookies = format!("{current}; {binding}");
    let token = mail.5.lock().unwrap().last().unwrap().clone();
    let body = serde_json::json!({"token":token,"confirmation":"delete my account"}).to_string();
    let completed = app
        .clone()
        .oneshot(post(
            "/v1/account/delete/finish",
            &body,
            Some(&cookies),
            Some("https://app.example"),
        ))
        .await
        .unwrap();
    assert_eq!(completed.status(), StatusCode::NO_CONTENT);
    assert!(
        completed
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .all(|h| h.to_str().unwrap().contains("Max-Age=0"))
    );
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/v1/session")
                .header(header::COOKIE, &current)
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users WHERE realm_id=$1")
        .bind(realm)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(auth.deliver_security_notice().await.unwrap());
    assert_eq!(*mail.2.lock().unwrap(), 2);
}
