//! Disposable native/SMTP test fixture. Never deploy as an authentication server.
mod database;
mod server;

#[path = "../support/smtp_fixture.rs"]
mod owned;

#[tokio::main]
async fn main() {
    let result = if std::env::args().nth(1).as_deref() == Some("--owned-fixture-server") {
        server::serve().await
    } else {
        owned::run("--owned-fixture-server").await
    };
    if result.is_err() {
        // Never reflect environment, mail contents, URLs or credentials.
        eprintln!("SMTP browser fixture failed");
        std::process::exit(1);
    }
}
