mod boundary;
mod consumers;
mod contract;
mod lifecycle;
mod revocation;
use crate::support::issuer_native::Fixture;
use crate::support::issuer_web::{ORIGIN, get, read, token_request};
use auth_core::*;
use axum::{http::header, response::Response};
use easy_auth_axum::{
    BrowserConfig, IssuerNativeWebServices, IssuerWebServices,
    experimental_issuer_native_web_router,
};
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;

async fn fixture(pool: PgPool) -> Fixture {
    wire(Fixture::new(pool).await)
}
fn wire(f: Fixture) -> Fixture {
    wire_with_inspection(f, false)
}
fn wire_with_inspection(mut f: Fixture, inspect: bool) -> Fixture {
    let services = IssuerWebServices::new(
        f.policy.authority().clone(),
        f.base.store.clone(),
        f.base.store.clone(),
        vec![f.base.key.clone()],
    )
    .unwrap();
    let services = IssuerNativeWebServices::new(
        services,
        f.base.store.clone(),
        f.base.store.clone(),
        f.base.store.clone(),
    );
    let services = if inspect {
        services.with_native_introspection(f.base.store.clone())
    } else {
        services
    };
    f.base.app = experimental_issuer_native_web_router(
        Auth::new(f.base.realm, f.base.store.clone(), f.mail.clone()),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        services,
    )
    .unwrap();
    f
}
async fn code(f: &Fixture) -> Secret {
    let (proofs, preview) = f.prepare().await;
    let response = f
        .send(
            "approve",
            &json!({"authorization":preview["authorization"]}),
            &proofs,
        )
        .await;
    assert_eq!(response.status(), 200);
    let returned = read(response).await;
    let url = url::Url::parse(returned["redirect_uri"].as_str().unwrap()).unwrap();
    Secret::parse(
        url.query_pairs()
            .find(|(k, _)| k == "code")
            .unwrap()
            .1
            .into_owned(),
    )
    .unwrap()
}
fn refresh_body(f: &Fixture, token: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("grant_type", "refresh_token")
        .append_pair("client_id", &f.base.client.client().to_string())
        .append_pair("refresh_token", token)
        .finish()
}
async fn refresh(f: &Fixture, token: &str) -> Response {
    f.base.send(refresh_body(f, token), None).await
}
async fn issued(f: &Fixture) -> Value {
    let response = f.base.send(f.base.body(&code(f).await), None).await;
    assert_eq!(response.status(), 200);
    read(response).await
}
fn status_body(client: uuid::Uuid, token: &str) -> String {
    url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", &client.to_string())
        .append_pair("token", token)
        .finish()
}
async fn revoke(f: &Fixture, token: &str) -> Response {
    f.base
        .app
        .clone()
        .oneshot(token_request(
            "/oidc/revoke",
            status_body(f.base.client.client(), token),
            None,
            true,
        ))
        .await
        .unwrap()
}
