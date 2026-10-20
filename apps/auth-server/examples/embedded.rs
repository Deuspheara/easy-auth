//! Run with the same environment as the server: cargo run -p easy-auth-server --example embedded
#[path = "embedded/application.rs"]
mod application;
use std::net::SocketAddr;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let easy_auth_server::ConfiguredApplication {
        auth,
        browser,
        router,
        bind,
    } = easy_auth_server::configured_application().await?;
    let notifications = easy_auth_server::notification_worker(auth.clone());
    let application = application::router(auth, browser).merge(router);
    let listener = tokio::net::TcpListener::bind(bind).await?;
    axum::serve(
        listener,
        application.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    notifications.abort();
    Ok(())
}
