//! Actual executable or embedded factory, with identical trusted settings.
use super::{FixtureResult, provision::Provision};
use std::{
    net::SocketAddr,
    process::{Child, Command, Stdio},
    time::Duration,
};
use zeroize::Zeroizing;

pub(super) struct Server(Child);
impl Server {
    pub async fn start(
        config: &serde_json::Value,
        database_name: &str,
        provision: &Provision,
    ) -> FixtureResult<(Self, SocketAddr)> {
        let origin = config["issuer"].as_str().ok_or("owned issuer required")?;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        drop(listener);
        let mut database = url::Url::parse(&std::env::var("DATABASE_URL")?)?;
        database.set_path(database_name);
        let database = Zeroizing::new(database.to_string());
        let mode = config["mode"].as_str().ok_or("owned mode required")?;
        let mut command = match mode {
            "standalone" => Command::new(
                config["server_binary"]
                    .as_str()
                    .ok_or("owned executable required")?,
            ),
            "embedded" => {
                let mut c = Command::new(std::env::current_exe()?);
                c.arg("--embedded");
                c
            }
            _ => return Err("invalid owned mode".into()),
        };
        let child = command
            .env_clear()
            .env("DATABASE_URL", database.as_str())
            .env("AUTH_DEVELOPMENT", "true")
            .env("AUTH_PUBLIC_URL", origin)
            .env("AUTH_BIND", address.to_string())
            .env("AUTH_REALM_ID", provision.realm.to_string())
            .env("AUTH_ISSUER_ENABLED", "true")
            .env("AUTH_ISSUER_KEY_ID", provision.key.to_string())
            .env("AUTH_ISSUER_KEY_FILE", &provision.key_file)
            .env("SMTP_HOST", "127.0.0.1")
            .env(
                "SMTP_PORT",
                std::env::var("EASY_AUTH_MAILPIT_SMTP_PORT").unwrap_or_else(|_| "1025".into()),
            )
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut owned = Self(child);
        let host = url::Url::parse(origin)?.authority().to_owned();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            if owned.0.try_wait()?.is_some() {
                use std::io::Read;
                let mut text = String::new();
                if let Some(stderr) = owned.0.stderr.take() {
                    stderr.take(4096).read_to_string(&mut text)?;
                }
                // Only fixed allowlisted categories escape; never return native
                // diagnostics, paths, configuration values or credentials.
                let category = [
                    "issuer requires an enabled current persisted signing key",
                    "issuer signing key input is unavailable or invalid",
                    "issuer signing key does not match the current persisted public key",
                    "database connection failed",
                    "issuer service configuration is invalid",
                    "development bind must be loopback",
                ]
                .into_iter()
                .find(|s| text.contains(s))
                .unwrap_or("unclassified");
                super::send(serde_json::json!({"phase":category}))?;
                return Err("owned server stopped during startup".into());
            }
            if healthy(address, &host).await {
                break;
            }
            if tokio::time::Instant::now() >= deadline {
                super::send(serde_json::json!({"phase":"readiness-timeout"}))?;
                return Err("owned server readiness timeout".into());
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        Ok((owned, address))
    }
    pub fn stop(mut self) -> FixtureResult<()> {
        self.0.kill()?;
        self.0.wait()?;
        Ok(())
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}
pub(super) async fn embedded() -> FixtureResult<()> {
    let application = easy_auth_server::configured_application().await?;
    let notifications = easy_auth_server::notification_worker(application.auth);
    let listener = tokio::net::TcpListener::bind(application.bind).await?;
    let result = axum::serve(
        listener,
        application
            .router
            .into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await;
    notifications.abort();
    result?;
    Ok(())
}

async fn healthy(address: SocketAddr, host: &str) -> bool {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Owned loopback process readiness only, outside SDK/production transport.
    tokio::time::timeout(Duration::from_secs(2), async {
        let mut socket = tokio::net::TcpStream::connect(address).await?;
        socket
            .write_all(
                format!("GET /healthz HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .await?;
        let mut status = [0; 12];
        socket.read_exact(&mut status).await?;
        Ok::<_, std::io::Error>(&status == b"HTTP/1.1 200")
    })
    .await
    .is_ok_and(|v| v.unwrap_or(false))
}
