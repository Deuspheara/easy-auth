use super::setup::{Fixture, ORIGIN};
use crate::support::cookie;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn linked_issuer_requires_the_actual_current_saml_session_source(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    let finished = f
        .deliver(
            "/v1/saml/sign-in/finish",
            &attempt,
            Some(&attempt.cookie),
            Some(ORIGIN),
        )
        .await;
    assert_eq!(finished.status(), 204);
    let current = cookie(&finished, "__Host-auth-session=");
    let response = f
        .app
        .clone()
        .oneshot(inventory_request(&current))
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let page: serde_json::Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(page["providers"].as_array().unwrap().len(), 1);
    assert_eq!(page["providers"][0]["kind"], "saml");
    assert_eq!(page["providers"][0]["issuer"], "urn:example:idp");
    assert_eq!(page["providers"][0].as_object().unwrap().len(), 3);
    let config = f.policy.registration();
    f.store
        .disable_saml_registration(config.realm(), config.connection(), config.client())
        .await
        .unwrap();
    let response = f.app.oneshot(inventory_request(&current)).await.unwrap();
    assert_eq!(response.status(), 401);
}

fn inventory_request(current: &str) -> Request<Body> {
    Request::builder()
        .uri("/v1/account/providers")
        .header("cookie", current)
        .body(Body::empty())
        .unwrap()
}
