use super::super::{GoogleDesktopCallback, GoogleDesktopError, GoogleDesktopListener};
use auth_core::Secret;
use std::{
    future::pending,
    net::{IpAddr, Ipv4Addr},
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    task::JoinHandle,
};

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
pub(super) async fn send(uri: &url::Url, request: &str) -> String {
    let mut stream = TcpStream::connect((
        uri.host_str().unwrap().trim_matches(['[', ']']),
        uri.port().unwrap(),
    ))
    .await
    .unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    let mut bytes = Vec::new();
    let read = tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .expect("test infrastructure: bounded actual socket response");
    if let Err(error) = read {
        // Closing with oversized unread bytes may reset TCP after Hyper's431.
        // Require an actual complete rejection response; reset alone proves nothing.
        assert_eq!(error.kind(), std::io::ErrorKind::ConnectionReset);
        assert!(
            bytes.starts_with(b"HTTP/1.1 431") && bytes.ends_with(b"\r\n\r\n"),
            "complete HTTP431 required before transport reset"
        );
    }
    String::from_utf8(bytes).unwrap()
}
pub(super) fn request(uri: &url::Url, query: &str) -> String {
    format!(
        "GET {}?{} HTTP/1.1\r\nHost: {}\r\n\r\n",
        uri.path(),
        query,
        uri.authority()
    )
}
pub(super) async fn stopped(uri: &url::Url) {
    assert!(
        TcpStream::connect((
            uri.host_str().unwrap().trim_matches(['[', ']']),
            uri.port().unwrap()
        ))
        .await
        .is_err(),
        "owned listener must be closed"
    );
}
