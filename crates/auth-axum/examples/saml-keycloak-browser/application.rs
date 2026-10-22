use super::{FixtureResult, mail::DisabledMail, observations::Observations};
use auth_core::{Auth, SamlIdentityPolicy};
use auth_postgres::Postgres;
use axum::{
    Router,
    extract::{Request, State},
    response::Response,
    routing::any,
};
use easy_auth_axum::{
    BrowserConfig, SamlAccountDeletionWebServices, SamlWebServices, experimental_saml_web_router,
};
use std::sync::Arc;
use tokio::sync::RwLock;
use tower::ServiceExt;

pub(super) fn build(
    store: Arc<Postgres>,
    origin: &str,
    policy: SamlIdentityPolicy,
    observations: Arc<Observations>,
) -> FixtureResult<Router> {
    let deletion = SamlAccountDeletionWebServices::new(
        policy.clone(),
        store.clone(),
        store.clone(),
        observations.clone(),
    )?;
    let services =
        SamlWebServices::new(policy.clone(), store.clone(), store.clone(), observations)?
            .with_account_deletion(deletion)?;
    Ok(experimental_saml_web_router(
        Auth::new(policy.registration().realm(), store, Arc::new(DisabledMail)),
        BrowserConfig::new(origin, false)?,
        services,
    )?)
}
/// Fixture-only trusted administrative selection between two fixed realm routers.
/// Browser fields do not select a source and every request still uses production routes.
pub(super) fn serve(current: Arc<RwLock<Router>>) -> Router {
    Router::new().fallback(any(forward)).with_state(current)
}
async fn forward(State(current): State<Arc<RwLock<Router>>>, request: Request) -> Response {
    let app = current.read().await.clone();
    app.oneshot(request)
        .await
        .expect("router service is infallible")
}
