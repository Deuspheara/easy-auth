//! Run with the same environment as the server: cargo run -p easy-auth-server --example embedded
use auth_axum::BrowserConfig;
use auth_core::{Auth, Error, User};
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode, header},
    routing::get,
};
use std::net::SocketAddr;
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
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (auth, browser, bind) = easy_auth_server::configured_auth().await?;
    let application = Router::new()
        .route("/private", get(private))
        .with_state(Application {
            auth: auth.clone(),
            browser: browser.clone(),
        })
        .merge(auth_axum::router(auth, browser));
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(
        listener,
        application.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}
