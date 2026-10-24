use crate::support::{Mail, app};
use auth_core::Auth;
use auth_postgres::Postgres;
use axum::{Router, body::Body, http::Request};
use easy_auth_axum::BrowserConfig;
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

async fn page(app: &Router, uri: &str) -> String {
    let response = app
        .clone()
        .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    assert!(!response.headers().contains_key("set-cookie"));
    let policy = response.headers()["content-security-policy"]
        .to_str()
        .unwrap();
    assert!(policy.contains("style-src 'sha256-"));
    assert!(!policy.contains("unsafe-inline"));
    String::from_utf8(
        response
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec(),
    )
    .unwrap()
}

fn capabilities(html: &str) -> Value {
    let value = html
        .split("id=\"capabilities\" type=\"hidden\" value='")
        .nth(1)
        .unwrap()
        .split('\'')
        .next()
        .unwrap();
    serde_json::from_str(value).unwrap()
}

#[sqlx::test]
async fn reference_ui_advertises_selected_services_without_creating_authority(pool: PgPool) {
    let (app, _) = app(pool.clone()).await;
    let html = page(&app, "/?passkeySignin=true&google=true").await;
    assert!(!html.contains("__CAPABILITIES__"));
    assert!(html.contains("<style>:root"));
    let caps = capabilities(&html);
    assert_eq!(caps["passwords"], true);
    assert!(
        caps.as_object()
            .unwrap()
            .iter()
            .all(|(name, value)| name == "passwords" || value == false)
    );
    for uri in [
        "/client.js",
        "/ui/browser-operations.js",
        "/ui/view.js",
        "/ui/signin.js",
        "/ui/account.js",
        "/ui/passkeys.js",
    ] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["content-type"],
            "text/javascript; charset=utf-8"
        );
        assert_eq!(response.headers()["cache-control"], "no-store");
        assert!(!response.headers().contains_key("set-cookie"));
    }
    for uri in ["/v1/passkeys", "/google/sign-in", "/saml/sign-in"] {
        let response = app
            .clone()
            .oneshot(Request::builder().uri(uri).body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 404);
    }
    let counts: (i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM auth_users),(SELECT count(*) FROM auth_sessions)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(counts, (0, 0));
}

#[sqlx::test]
async fn reference_ui_does_not_infer_password_service_from_routes_or_compiled_features(
    pool: PgPool,
) {
    let store = Postgres::new(pool);
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let app = easy_auth_axum::router(
        Auth::new(realm, Arc::new(store), Arc::new(Mail::default())),
        BrowserConfig::new("https://app.example", false).unwrap(),
    );
    let html = page(&app, "/").await;
    assert!(
        capabilities(&html)
            .as_object()
            .unwrap()
            .values()
            .all(|value| value == false)
    );
}
