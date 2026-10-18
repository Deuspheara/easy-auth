use async_trait::async_trait;
use auth_core::{Auth, EmailDelivery, PasswordService, Secret};
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use easy_auth_axum::BrowserConfig;
use sqlx::PgPool;
use std::sync::{Arc, Mutex};
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Default)]
pub(crate) struct Mail(
    pub(crate) Mutex<Vec<String>>,
    pub(crate) Mutex<Vec<String>>,
    pub(crate) Mutex<usize>,
    pub(crate) Mutex<bool>,
    pub(crate) Mutex<Vec<(String, String)>>,
    pub(crate) Mutex<Vec<String>>,
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
