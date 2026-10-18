use async_trait::async_trait;
use auth_axum::BrowserConfig;
use auth_core::{Auth, EmailDelivery, Error, PasswordService, Secret};
use auth_postgres::Postgres;
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    transport::smtp::authentication::Credentials,
};
use sqlx::postgres::PgPoolOptions;
use std::{env, net::SocketAddr, sync::Arc, time::Duration};
use uuid::Uuid;

struct Smtp {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from: lettre::message::Mailbox,
    origin: String,
}
impl Smtp {
    async fn send(&self, email: &str, subject: &str, body: String) -> auth_core::Result<()> {
        let message = Message::builder()
            .from(self.from.clone())
            .to(email.parse().map_err(|_| Error::InvalidInput)?)
            .subject(subject)
            .body(body)
            .map_err(|_| Error::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(10), self.transport.send(message))
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}
#[async_trait]
impl EmailDelivery for Smtp {
    async fn password_reset(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        self.send(email,"Password reset request",format!("A password reset was requested. If this mailbox has a password credential, open this link in the browser that requested it. The link expires in ten minutes and works once.\n\n{}/reset#token={}\n\nIf you did not request this, ignore this email. No account changes have been made.",self.origin,token.expose())).await
    }
    async fn password_changed(&self, email: &str) -> auth_core::Result<()> {
        self.send(email,"Your password was reset",format!("Your password was reset. Existing sessions and outstanding sign-in/recovery links were invalidated. Sign in again at {}/ using the new password.\n\nIf you did not make this change, your mailbox or account may be compromised. Secure your mailbox and contact the service operator through a trusted channel. This message contains no sign-in link or password.",self.origin)).await
    }
    async fn sign_in(&self, email: &str, token: &Secret) -> auth_core::Result<()> {
        let to = email.parse().map_err(|_| Error::InvalidInput)?;
        let message = Message::builder().from(self.from.clone()).to(to).subject("Your sign-in link")
            .body(format!("Open in the browser that requested sign-in. This link expires in ten minutes and works once.\n\n{}/#token={}\n\nIf you did not request this, ignore this email.", self.origin, token.expose()))
            .map_err(|_| Error::Unavailable)?;
        tokio::time::timeout(Duration::from_secs(10), self.transport.send(message))
            .await
            .map_err(|_| Error::Unavailable)?
            .map_err(|_| Error::Unavailable)?;
        Ok(())
    }
}
fn setting(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

/// Compose database, email and shared auth for the binary or embedded example.
/// Values are validated before returning; no configuration secrets are logged.
pub async fn configured_auth()
-> Result<(Auth, BrowserConfig, SocketAddr), Box<dyn std::error::Error>> {
    let development = match setting("AUTH_DEVELOPMENT", "false").as_str() {
        "true" => true,
        "false" => false,
        _ => return Err("AUTH_DEVELOPMENT must be true or false".into()),
    };
    let browser = BrowserConfig::new(
        &setting("AUTH_PUBLIC_URL", "http://127.0.0.1:8080"),
        development,
    )?;
    let bind: SocketAddr = setting("AUTH_BIND", "127.0.0.1:8080").parse()?;
    if development && !bind.ip().is_loopback() {
        return Err("development bind must be loopback".into());
    }
    let realm: Uuid = env::var("AUTH_REALM_ID")
        .map_err(|_| "AUTH_REALM_ID is required")?
        .parse()?;
    let smtp_host = setting("SMTP_HOST", "localhost");
    let smtp_port: u16 = setting("SMTP_PORT", if development { "1025" } else { "465" }).parse()?;
    let mut smtp = if development {
        if !matches!(smtp_host.as_str(), "localhost" | "127.0.0.1" | "::1") {
            return Err("development SMTP must be loopback".into());
        }
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp_host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp_host)?
    }
    .port(smtp_port)
    .timeout(Some(Duration::from_secs(10)));
    match (env::var("SMTP_USERNAME"), env::var("SMTP_PASSWORD")) {
        (Ok(user), Ok(password)) if !user.is_empty() && !password.is_empty() => {
            smtp = smtp.credentials(Credentials::new(user, password))
        }
        (Err(_), Err(_)) if development => (),
        _ => {
            return Err(
                "SMTP_USERNAME and SMTP_PASSWORD are required together in production".into(),
            );
        }
    }
    let mailer = Smtp {
        transport: smtp.build(),
        from: setting("SMTP_FROM", "auth@localhost.test").parse()?,
        origin: browser.origin().to_owned(),
    };
    let database_url = env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is required")?;
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(Duration::from_secs(5))
        .connect(&database_url)
        .await
        .map_err(|_| "database connection failed")?;
    let repository = Postgres::new(pool);
    repository.migrate().await?;
    repository.ensure_realm(realm).await?;
    let mut auth = Auth::new(realm, Arc::new(repository), Arc::new(mailer));
    let blocklist = match env::var("AUTH_PASSWORD_BLOCKLIST_FILE") {
        Ok(path) => Some(path),
        Err(env::VarError::NotPresent) => None,
        Err(_) => return Err("AUTH_PASSWORD_BLOCKLIST_FILE must be valid Unicode".into()),
    };
    if let Some(path) = blocklist {
        // Limit startup memory: one local UTF-8 file, at most 32 MiB. Never log contents.
        use std::io::Read;
        let file = std::fs::File::open(path).map_err(|_| "password blocklist cannot be opened")?;
        let mut corpus = zeroize::Zeroizing::new(String::new());
        file.take(32 * 1024 * 1024 + 1)
            .read_to_string(&mut corpus)
            .map_err(|_| "password blocklist must be UTF-8")?;
        if corpus.len() > 32 * 1024 * 1024 {
            return Err("password blocklist exceeds 32 MiB".into());
        }
        let passwords = PasswordService::new(&corpus)?;
        if !development && passwords.corpus_size() < 10_000 {
            return Err(
                "production password blocklist requires at least 10000 distinct eligible passwords"
                    .into(),
            );
        }
        auth = auth.with_passwords(Arc::new(passwords));
    }
    if development {
        tracing::warn!("development_http_and_smtp_enabled");
    }
    Ok((auth, browser, bind))
}

/// Start the bounded notification worker alongside either server composition.
/// Keep the handle; abort it at shutdown. Unacknowledged claims become retryable after the lease.
pub fn notification_worker(auth: Auth) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            match auth.deliver_password_reset_notice().await {
                Ok(true) => (),
                Ok(false) => tokio::time::sleep(Duration::from_secs(1)).await,
                Err(_) => {
                    tracing::warn!("password_reset_notification_delivery_failed");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                }
            }
        }
    })
}
