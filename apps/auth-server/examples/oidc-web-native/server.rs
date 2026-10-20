use super::{FixtureResult, application, configuration, embedded, read_command, send, transport};
use serde_json::json;
use std::{io::BufRead, net::SocketAddr, time::Duration};
use tokio::{net::TcpListener, sync::oneshot};

pub(super) async fn run(input: &mut impl BufRead) -> FixtureResult<()> {
    let config = read_command(input)?.ok_or("missing owned TLS configuration")?;
    transport::initialize(&config)?;
    // Exercise the actual compatibility refusal, not any broad Err or failed DB.
    let refused = configuration::configured_auth()
        .await
        .err()
        .ok_or("auth-only API accepted enabled browser settings")?;
    if refused.to_string() != "OIDC browser settings require configured_application" {
        return Err("unexpected compatibility refusal".into());
    }
    let application::ConfiguredApplication {
        auth,
        browser,
        router,
        bind,
    } = application::configured_application().await?;
    let notifications = easy_auth_server::notification_worker(auth.clone());
    let router = match config["mode"].as_str() {
        Some("standalone") => router,
        Some("embedded") => embedded::router(auth, browser).merge(router),
        _ => return Err("explicit supported fixture mode required".into()),
    };
    let listener = TcpListener::bind(bind).await?;
    let address = listener.local_addr()?;
    if !address.ip().is_loopback() {
        return Err("owned application listener must be loopback".into());
    }
    let (shutdown, stopped) = oneshot::channel();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(async {
            let _ = stopped.await;
        })
        .await
    });
    send(
        json!({"ready":true,"application_address":address.to_string(),"auth_only_refused":true,"public_login_only":true}),
    )?;
    while let Some(command) = read_command(input)? {
        if command["command"].as_str() == Some("close") {
            break;
        }
        send(json!({"id":command["id"],"result":"unsupported_command"}))?;
    }
    let _ = shutdown.send(());
    let completed = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .map_err(|_| "owned server shutdown deadline")?;
    completed??;
    notifications.abort();
    let _ = notifications.await;
    send(json!({"server_stopped":true}))?;
    Ok(())
}
