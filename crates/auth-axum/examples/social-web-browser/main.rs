//! Owned HTTPS-browser/code/PostgreSQL fixture only. Never deploy.
mod fixture;

#[tokio::main]
async fn main() {
    if fixture::run(false).await.is_err() {
        eprintln!("Owned social web fixture failed");
        std::process::exit(1);
    }
}
