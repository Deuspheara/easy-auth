use std::net::SocketAddr;
#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("easy_auth=info,easy_auth_axum=info")
        .init();
    let (auth, browser, bind) = easy_auth_server::configured_auth().await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    tracing::info!("auth_server_started");
    axum::serve(
        listener,
        auth_axum::router(auth, browser).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async { shutdown_signal().await })
    .await?;
    Ok(())
}
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        if let Ok(mut signal) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! { _ = tokio::signal::ctrl_c() => (), _ = signal.recv() => () }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}
