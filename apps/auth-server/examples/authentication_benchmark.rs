//! Synthetic owned-fixture measurements; use scripts/benchmark_authentication.py.
#[path = "authentication_benchmark/load.rs"]
mod load;
#[path = "authentication_benchmark/passwords.rs"]
mod passwords;
#[path = "authentication_benchmark/sessions.rs"]
mod sessions;

#[tokio::main]
async fn main() {
    let result = match std::env::args().nth(1).as_deref() {
        Some("sessions") => sessions::run().await,
        Some("argon2") => passwords::run().await,
        _ => Err("select an owned benchmark profile".into()),
    };
    match result {
        Ok(report) => println!("{report}"),
        Err(_) => {
            // Database errors may include connection details; never format them.
            eprintln!("owned authentication benchmark failed");
            std::process::exit(1);
        }
    }
}
