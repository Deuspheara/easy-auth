//! Owned feature-disabled persistence probe only. Never deploy.
mod deletion;
mod input;
mod preservation;
type ProbeResult<T> = Result<T, Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() {
    if deletion::run().await.is_err() {
        eprintln!("Owned grant erasure probe failed");
        std::process::exit(1);
    }
}
