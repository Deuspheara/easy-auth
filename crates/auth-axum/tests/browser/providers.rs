use crate::support::{app, linked_provider_records, sign_in};
use auth_core::ProviderKind;
use axum::{body::Body, http::Request};
use http_body_util::BodyExt;
use serde_json::Value;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

#[sqlx::test]
async fn provider_inventory_contains_only_public_owner_metadata(pool: PgPool) {
    let (app, mail) = app(pool.clone()).await;
    let current = sign_in(&app, &mail, "owner@example.test").await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/session")
                .header("cookie", &current)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let owner: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let realm = Uuid::parse_str(owner["realm_id"].as_str().unwrap()).unwrap();
    let user = Uuid::parse_str(owner["id"].as_str().unwrap()).unwrap();
    for kind in [ProviderKind::Oidc, ProviderKind::Saml] {
        linked_provider_records::insert(&pool, realm, user, Uuid::new_v4(), kind).await;
    }
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/account/providers")
                .header("cookie", &current)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.headers()["cache-control"], "no-store");
    assert_eq!(response.headers()["referrer-policy"], "no-referrer");
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let page: Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(page["providers"].as_array().unwrap().len(), 2);
    assert!(page["next"].is_null());
    for provider in page["providers"].as_array().unwrap() {
        assert_eq!(provider.as_object().unwrap().len(), 3);
        assert!(provider["id"].is_string());
        assert!(provider["issuer"].is_string());
        assert!(provider["kind"] == "oidc" || provider["kind"] == "saml");
    }
    let text = std::str::from_utf8(&body).unwrap();
    for forbidden in [
        "subject", "token", "email", "user_id", "private-", "verifier",
    ] {
        assert!(!text.contains(forbidden));
    }
}

#[sqlx::test]
async fn provider_inventory_rejects_owner_selectors_partial_cursors_and_missing_proof(
    pool: PgPool,
) {
    let (app, mail) = app(pool).await;
    let current = sign_in(&app, &mail, "owner@example.test").await;
    for suffix in [
        "?realm_id=00000000-0000-0000-0000-000000000000",
        "?after_kind=oidc",
        "?after_id=00000000-0000-0000-0000-000000000000",
        "?after_kind=apple&after_id=00000000-0000-0000-0000-000000000000",
        "?after_kind=oidc&after_kind=saml&after_id=00000000-0000-0000-0000-000000000000",
    ] {
        let response = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri(format!("/v1/account/providers{suffix}"))
                    .header("cookie", &current)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), 400);
    }
    for cookie in [None, Some(format!("{current}; {current}"))] {
        let mut request = Request::builder().uri("/v1/account/providers");
        if let Some(cookie) = cookie {
            request = request.header("cookie", cookie);
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), 401);
    }
}

#[sqlx::test]
async fn provider_inventory_contract_has_no_owner_selector_or_mutation(pool: PgPool) {
    let (app, _) = app(pool).await;
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/openapi.json")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let spec: Value =
        serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap();
    let path = &spec["paths"]["/v1/account/providers"];
    assert_eq!(path.as_object().unwrap().len(), 1);
    assert!(path["get"].is_object());
    let parameters = path["get"]["parameters"].as_array().unwrap();
    assert_eq!(parameters.len(), 3);
    assert!(
        parameters
            .iter()
            .all(|p| ["after_kind", "after_id", "Cookie"].contains(&p["name"].as_str().unwrap()))
    );
    assert_eq!(
        spec["components"]["schemas"]["LinkedProvidersResponse"]["properties"]["providers"]["maxItems"],
        50
    );
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/account/providers")
                .header("origin", "https://app.example")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), 405);
}
