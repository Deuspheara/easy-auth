use super::setup::{Fixture, body, session};
use axum::{body::Body, http::Request};
use sqlx::PgPool;

#[sqlx::test]
async fn linked_issuer_requires_the_actual_current_oidc_session_source(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let attempt = f.start().await;
    let finished = f.post("finish", attempt.callback, &attempt.cookie).await;
    assert_eq!(finished.status(), 204);
    let current = session(&finished);
    let response = f.send(inventory_request(&current)).await;
    assert_eq!(response.status(), 200);
    let page = body(response).await;
    assert_eq!(page["providers"].as_array().unwrap().len(), 1);
    assert_eq!(page["providers"][0]["kind"], "oidc");
    assert_eq!(page["providers"][0]["issuer"], "https://issuer.example");
    assert_eq!(page["providers"][0].as_object().unwrap().len(), 3);
    let config = f.policy.configuration();
    f.store
        .disable_oauth_connection(config.realm(), config.connection(), config.client())
        .await
        .unwrap();
    assert_eq!(f.send(inventory_request(&current)).await.status(), 401);
}

fn inventory_request(current: &str) -> Request<Body> {
    Request::builder()
        .uri("/v1/account/providers")
        .header("cookie", current)
        .body(Body::empty())
        .unwrap()
}
