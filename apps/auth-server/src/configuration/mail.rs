use super::{optional_setting, setting};
use crate::smtp::Smtp;
use auth_axum::BrowserConfig;
use lettre::{AsyncSmtpTransport, Tokio1Executor, transport::smtp::authentication::Credentials};
use std::time::Duration;

pub(super) fn delivery(
    browser: &BrowserConfig,
    development: bool,
) -> Result<Smtp, Box<dyn std::error::Error>> {
    let smtp_host = setting("SMTP_HOST", "localhost")?;
    let smtp_port: u16 = setting("SMTP_PORT", if development { "1025" } else { "465" })?
        .parse()
        .map_err(|_| "SMTP_PORT must be a valid port number")?;
    let mut smtp = if development {
        if !matches!(smtp_host.as_str(), "localhost" | "127.0.0.1" | "::1") {
            return Err("development SMTP must be loopback".into());
        }
        AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&smtp_host)
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&smtp_host)
            .map_err(|_| "SMTP_HOST cannot configure a TLS relay")?
    }
    .port(smtp_port)
    .timeout(Some(Duration::from_secs(10)));
    match (
        optional_setting("SMTP_USERNAME")?,
        optional_setting("SMTP_PASSWORD")?,
    ) {
        (Some(user), Some(password)) if !user.is_empty() && !password.is_empty() => {
            smtp = smtp.credentials(Credentials::new(user, password))
        }
        (None, None) if development => (),
        _ => {
            return Err(
                "SMTP_USERNAME and SMTP_PASSWORD are required together in production".into(),
            );
        }
    }
    let mailer = Smtp {
        transport: smtp.build(),
        from: setting("SMTP_FROM", "auth@localhost.test")?
            .parse()
            .map_err(|_| "SMTP_FROM must be a valid mailbox")?,
        origin: browser.origin().to_owned(),
    };
    Ok(mailer)
}
