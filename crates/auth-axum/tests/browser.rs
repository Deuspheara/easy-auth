use async_trait::async_trait;
use auth_core::{Auth, EmailDelivery, Secret};
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
struct Mail(Mutex<Vec<String>>);
#[async_trait]
impl EmailDelivery for Mail {
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
            Auth::new(realm, Arc::new(store), mail.clone()),
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
