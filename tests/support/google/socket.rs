use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

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
