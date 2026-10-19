mod boundary;
mod contract;

use crate::support::{Mail, cookie, post};
use auth_core::{Auth, PasskeyEnrollment, PasskeyService, PasskeySignIn, PasskeySignup, Secret};
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
};
use easy_auth_axum::{BrowserConfig, experimental_passkey_signup_router, passkey_signup_openapi};
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://app.example";
const START: &str = "/v1/passkeys/signup/start";
const REGISTRATION: &str = "/v1/passkeys/signup/registration";
const FINISH: &str = "/v1/passkeys/signup/finish";

async fn app(pool: PgPool) -> (Router, Auth, Arc<Postgres>) {
    let store = Arc::new(Postgres::new(pool));
    store.migrate().await.unwrap();
    let realm = Uuid::new_v4();
    store.ensure_realm(realm).await.unwrap();
    let service = Arc::new(PasskeyService::new(ORIGIN, "Example").unwrap());
    let enrollment = Arc::new(PasskeyEnrollment::new(
        realm,
        service.clone(),
        store.clone(),
    ));
    let sign_in = Arc::new(PasskeySignIn::new(realm, service.clone(), store.clone()));
    let signup = Arc::new(PasskeySignup::new(realm, service, store.clone()));
    let auth = Auth::new(realm, store.clone(), Arc::new(Mail::default()));
    let app = experimental_passkey_signup_router(
        auth.clone(),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        enrollment,
        sign_in,
        signup,
    )
    .unwrap();
    (app, auth, store)
}

async fn json(response: Response) -> serde_json::Value {
    serde_json::from_slice(&response.into_body().collect().await.unwrap().to_bytes()).unwrap()
}

fn registration() -> serde_json::Value {
    serde_json::json!({"id":"AQ","rawId":"AQ","type":"public-key",
        "response":{"attestationObject":"AA","clientDataJSON":"e30"}})
}

fn assertion() -> serde_json::Value {
    serde_json::json!({"id":"AQ","rawId":"AQ","type":"public-key",
        "response":{"authenticatorData":"AQ","clientDataJSON":"e30","signature":"AQ"}})
}
