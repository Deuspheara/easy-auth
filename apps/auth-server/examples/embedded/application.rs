use auth_axum::BrowserConfig;
use auth_core::{Auth, Error, User};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::get,
};
#[derive(Clone)]
struct Application {
    auth: Auth,
    browser: BrowserConfig,
}
async fn private(
    State(app): State<Application>,
    headers: HeaderMap,
) -> Result<([(header::HeaderName, &'static str); 1], Json<User>), StatusCode> {
    auth_axum::authenticate(&app.auth, &app.browser, &headers)
        .await
        .map(|user| ([(header::CACHE_CONTROL, "no-store")], Json(user)))
        .map_err(|error| match error {
            Error::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            _ => StatusCode::UNAUTHORIZED,
        })
}

/// Application-owned routes use the same auth/browser snapshot as the library router.
pub(super) fn router(auth: Auth, browser: BrowserConfig) -> Router {
    Router::new()
        .route("/private", get(private))
        .with_state(Application { auth, browser })
}
