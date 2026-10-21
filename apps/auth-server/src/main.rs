mod runtime;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    runtime::serve().await
}
