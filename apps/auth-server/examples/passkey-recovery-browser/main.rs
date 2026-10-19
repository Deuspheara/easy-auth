//! Owned native recovery/SMTP fixture. Never deploy as an authentication server.
#[path = "../passkey-smtp-browser/database.rs"]
mod baseline;
mod clock;
mod database;
mod manual;
#[path = "../support/smtp_fixture.rs"]
mod owned;
mod server;

#[tokio::main]
async fn main() {
    let result = if std::env::args().nth(1).as_deref() == Some("--owned-recovery-server") {
        server::serve().await
    } else {
        owned::run("--owned-recovery-server").await
    };
    if result.is_err() {
        eprintln!("Recovery browser fixture failed");
        std::process::exit(1);
    }
}
