mod mail;
#[cfg(feature = "oidc-account-deletion")]
pub(crate) mod oidc_provider;
pub(crate) use mail::Mail;

use auth_core::{Auth, PasswordService};
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use easy_auth_axum::BrowserConfig;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

pub(crate) async fn app(pool: PgPool) -> (Router, Arc<Mail>) {
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
pub(crate) fn post(
    path: &str,
    body: &str,
    cookie: Option<&str>,
    origin: Option<&str>,
) -> Request<Body> {
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
pub(crate) fn cookie(response: &axum::response::Response, name: &str) -> String {
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
pub(crate) async fn sign_in(app: &Router, mail: &Mail, email: &str) -> String {
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
    let token = mail.sign_ins.lock().unwrap().last().unwrap().clone();
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
