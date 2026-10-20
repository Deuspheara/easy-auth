//! Explicit public-provider GET preflight. No browser, credentials or token POSTs.
#[path = "../../../../tests/support/google/database.rs"]
mod database;
mod network;
mod probe;
mod setup;

type ProbeResult<T> = Result<T, &'static str>;

#[tokio::main]
async fn main() {
    match run().await {
        Ok(report) => println!("{report}"),
        Err(stage) => {
            eprintln!("{}", serde_json::json!({"status":"failed","stage":stage}));
            std::process::exit(1);
        }
    }
}

async fn run() -> ProbeResult<serde_json::Value> {
    let arguments: Vec<_> = std::env::args().skip(1).collect();
    let mode = match arguments.as_slice() {
        [mode] if mode == "--public-metadata" || mode == "--check-cleanup-on-failure" => mode,
        _ => return Err("explicit_preflight_mode_required"),
    };
    let database = database::Database::create().await?;
    // Cleanup runs after every probe outcome; no early ? may skip owned DB close.
    let result = if mode == "--check-cleanup-on-failure" {
        Err("injected_probe_failure")
    } else {
        probe::run(&database.pool).await
    };
    database.close().await?;
    let mut report = result?;
    report["owned_database_removed"] = true.into();
    Ok(report)
}
