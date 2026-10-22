use super::setup::{Fixture, ORIGIN};
use crate::support::post;
use crate::support::saml_provider as provider;
use auth_core::{SamlIdentityPolicy, SamlRegistration};
use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use easy_auth_axum::{
    BrowserConfig, SamlAccountDeletionWebServices, SamlWebServices,
    experimental_oidc_saml_web_router,
};
use http_body_util::BodyExt;
use sqlx::PgPool;
use tower::ServiceExt;
use uuid::Uuid;

#[sqlx::test(migrations = "../auth-postgres/migrations")]
async fn shared_router_preserves_both_contracts_and_origin_boundaries(pool: PgPool) {
    let f = Fixture::new(pool).await;
    let reg = SamlRegistration::unsigned_redirect(
        f.auth.realm(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "urn:combined:sp",
        "urn:combined:idp",
        "https://idp.example/sso",
        "https://app.example/saml/acs",
    )
    .unwrap();
    let policy = f
        .store
        .configure_saml_identity_policy(&SamlIdentityPolicy::new(reg), &provider::trust())
        .await
        .unwrap();
    let deletion = SamlAccountDeletionWebServices::new(
        policy.clone(),
        f.store.clone(),
        f.store.clone(),
        f.store.clone(),
    )
    .unwrap();
    let saml = SamlWebServices::new(
        policy.clone(),
        f.store.clone(),
        f.store.clone(),
        f.store.clone(),
    )
    .unwrap()
    .with_account_deletion(deletion)
    .unwrap();
    let app = experimental_oidc_saml_web_router(
        f.auth.clone(),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        f.services.clone(),
        saml,
    )
    .unwrap();
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
    assert_eq!(response.status(), StatusCode::OK);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let spec: serde_json::Value = serde_json::from_slice(&body).unwrap();
    for path in [
        "/v1/session",
        "/v1/saml/account-delete/finish",
        "/v1/account/provider-delete/finish",
        "/oidc/callback",
        "/saml/acs",
        "/v1/oidc/sign-in/start",
        "/v1/saml/sign-in/start",
    ] {
        assert!(
            spec["paths"].get(path).is_some(),
            "combined contract missing {path}"
        );
    }
    for path in ["/v1/oidc/sign-in/start", "/v1/saml/sign-in/start"] {
        let response = app
            .clone()
            .oneshot(post(path, "{}", None, Some("https://wrong.example")))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        let response = app
            .clone()
            .oneshot(post(path, "{}", None, Some(ORIGIN)))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);
        if path.contains("/saml/") {
            let body = response.into_body().collect().await.unwrap().to_bytes();
            let result: serde_json::Value = serde_json::from_slice(&body).unwrap();
            let url = result["authorization_url"].as_str().unwrap();
            let response = provider::response_field_from(
                policy.registration(),
                url,
                saml_rs::NameId::new("combined-subject", Some(saml_rs::NameIdFormat::Persistent)),
                policy.registration().idp_entity(),
                std::time::Duration::from_secs(180),
            );
            let relay = url::Url::parse(url)
                .unwrap()
                .query_pairs()
                .find(|(k, _)| k == "RelayState")
                .unwrap()
                .1
                .into_owned();
            let form = url::form_urlencoded::Serializer::new(String::new())
                .append_pair("SAMLResponse", &response)
                .append_pair("RelayState", &relay)
                .finish();
            let response = app
                .clone()
                .oneshot(
                    Request::builder()
                        .method("POST")
                        .uri("/saml/acs")
                        .header("content-type", "application/x-www-form-urlencoded")
                        .header("origin", "https://idp.example")
                        .body(Body::from(form))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            assert!(response.headers().get("set-cookie").is_none());
        }
    }
    let logout = app
        .oneshot(post("/v1/logout", "{}", None, Some(ORIGIN)))
        .await
        .unwrap();
    assert_eq!(logout.status(), StatusCode::NO_CONTENT);
    let cleared: Vec<_> = logout
        .headers()
        .get_all("set-cookie")
        .iter()
        .map(|v| v.to_str().unwrap())
        .collect();
    for name in [
        "__Host-auth-oidc-signin-browser",
        "__Host-auth-oidc-delete-browser",
        "__Host-auth-saml-browser",
        "__Host-auth-saml-delete-browser",
    ] {
        assert!(
            cleared
                .iter()
                .any(|value| value.starts_with(name) && value.contains("Max-Age=0")),
            "missing provider proof cleanup: {name}"
        );
    }
    let users: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users")
        .fetch_one(&f.pool)
        .await
        .unwrap();
    assert_eq!(users, 0);
}
