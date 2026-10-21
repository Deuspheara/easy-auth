use std::net::SocketAddr;

pub(super) async fn serve() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter("easy_auth=info,easy_auth_axum=info")
        .init();
    let easy_auth_server::ConfiguredApplication {
        auth, router, bind, ..
    } = easy_auth_server::configured_application().await?;
    let listener = tokio::net::TcpListener::bind(bind).await?;
    let notifications = easy_auth_server::notification_worker(auth.clone());
    tracing::info!("auth_server_started");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async { shutdown_signal().await })
    .await?;
    notifications.abort();
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
