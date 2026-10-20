//! Owned browser transport fixture; stdout is private protocol IPC to its parent.
//! No Google provider, account, SQL authority or credential data is involved.
use auth_core::Secret;
use easy_auth_server::GoogleDesktopListener;
use serde_json::json;
use std::{
    future::pending,
    net::{IpAddr, Ipv4Addr},
    time::{SystemTime, UNIX_EPOCH},
};

#[tokio::main]
async fn main() {
    if run().await.is_err() {
        eprintln!("Owned desktop browser fixture failed");
        std::process::exit(1);
    }
}
async fn run() -> Result<(), ()> {
    let listener = GoogleDesktopListener::bind(IpAddr::V4(Ipv4Addr::LOCALHOST), "/owned-return")
        .await
        .map_err(|_| ())?;
    let state = Secret::generate().map_err(|_| ())?;
    let query = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("state", state.expose())
        .append_pair("iss", "https://accounts.google.com")
        .append_pair("code", "owned-browser-code")
        .finish();
    // Parent captures this in memory and never forwards it to logs/reports.
    println!(
        "{}",
        json!({"return_url":format!("{}?{query}", listener.redirect().as_str())})
    );
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| ())?
        .as_micros();
    let expiry = i64::try_from(now).map_err(|_| ())? + 120_000_000;
    let _received = listener
        .receive(&state, expiry, pending())
        .await
        .map_err(|_| ())?;
    println!("{}", json!({"received":true}));
    Ok(())
}
