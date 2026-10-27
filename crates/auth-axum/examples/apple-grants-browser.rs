//! Owned captured-grant HTTPS/PG fixture only. Never deploy.
#[path = "social-web-browser/fixture.rs"]
mod fixture;

#[tokio::main]
async fn main() {
    if fixture::run(true).await.is_err() {
        eprintln!("Owned Apple grant fixture failed");
        std::process::exit(1);
    }
}
