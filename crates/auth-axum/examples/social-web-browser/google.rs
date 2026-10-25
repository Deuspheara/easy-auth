use super::google_provider as provider;
#[path = "../google-web-browser/authorize.rs"]
mod authorize;
use auth_core::OAuthConnection;
use axum::{Router, routing::get};
use sqlx::PgPool;
use std::sync::Arc;

pub(super) fn routes(
    pool: &PgPool,
    configuration: &OAuthConnection,
    provider: Arc<provider::Provider>,
) -> Router {
    Router::new()
        .route("/fixture/google/authorize", get(authorize::response))
        .with_state(authorize::Source {
            pool: pool.clone(),
            configuration: configuration.clone(),
            provider,
        })
}
