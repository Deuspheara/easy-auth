//! Anonymous public HTTP probe. Browser cookies and RP tokens are separate APIs.
mod probe;
use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    match probe::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => {
            // HTTP errors can contain URLs. Emit no raw input or diagnostics.
            eprintln!("Public HTTP probe failed; check origin, TLS and service status.");
            ExitCode::FAILURE
        }
    }
}
