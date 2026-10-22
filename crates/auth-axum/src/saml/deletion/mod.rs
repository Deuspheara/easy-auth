pub(super) mod handlers;
pub(super) mod pages;
mod services;
pub(super) mod types;

use super::routing::WebState;
use axum::{
    Router,
    routing::{get, post},
};
pub use services::SamlAccountDeletionWebServices;

pub(super) fn routes() -> Router<WebState> {
    Router::new()
        .route("/v1/saml/account-delete/start", post(handlers::start))
        .route("/v1/saml/account-delete/finish", post(handlers::finish))
        .route("/v1/saml/account-delete/cancel", post(handlers::cancel))
        .route("/saml/account-delete", get(pages::page))
        .route("/saml/account-delete.js", get(pages::script))
}
