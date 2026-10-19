mod boundary;
mod contract;

use crate::support::{Mail, cookie, post};
use auth_core::{Auth, PasskeyEnrollment, PasskeyService, PasskeySignIn};
use auth_postgres::Postgres;
use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
};
use easy_auth_axum::{BrowserConfig, experimental_passkey_router, passkey_authentication_openapi};
use http_body_util::BodyExt;
use sqlx::PgPool;
use std::sync::Arc;
use tower::ServiceExt;
use uuid::Uuid;

const ORIGIN: &str = "https://app.example";
const START: &str = "/v1/passkeys/authentication/start";
const FINISH: &str = "/v1/passkeys/authentication/finish";

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
    let sign_in = Arc::new(PasskeySignIn::new(realm, service, store.clone()));
    let auth = Auth::new(realm, store.clone(), Arc::new(Mail::default()));
    let app = experimental_passkey_router(
        auth.clone(),
        BrowserConfig::new(ORIGIN, false).unwrap(),
        enrollment,
        sign_in,
    )
    .unwrap();
    (app, auth, store)
}
