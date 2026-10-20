use super::super::{GoogleDesktopCallback, GoogleDesktopError, GoogleDesktopListener};
pub(super) use super::socket::{request, send, stopped};
use auth_core::Secret;
use std::{
    future::pending,
    net::{IpAddr, Ipv4Addr},
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::task::JoinHandle;

pub(super) fn expiry() -> i64 {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_micros(),
    )
    .unwrap()
        + 30_000_000
}
pub(super) async fn listener() -> GoogleDesktopListener {
    GoogleDesktopListener::bind(IpAddr::V4(Ipv4Addr::LOCALHOST), "/owned/return")
        .await
        .unwrap()
}
pub(super) fn query(state: &Secret, error: Option<&str>) -> String {
    let mut form = url::form_urlencoded::Serializer::new(String::new());
    form.append_pair("state", state.expose())
        .append_pair("iss", "https://accounts.google.com");
    if let Some(error) = error {
        form.append_pair("error", error)
            .append_pair("error_description", "private-foreign-detail");
    } else {
        form.append_pair("code", "owned-private-code")
            .append_pair("scope", "openid email")
            .append_pair("authuser", "0");
    }
    form.finish()
}
pub(super) fn start(
    listener: GoogleDesktopListener,
    state: Secret,
) -> JoinHandle<Result<GoogleDesktopCallback, GoogleDesktopError>> {
    tokio::spawn(async move { listener.receive(&state, expiry(), pending()).await })
}
