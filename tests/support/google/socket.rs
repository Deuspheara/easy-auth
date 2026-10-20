use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream},
};

const CLOSURE_STEP_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_CLOSURE_OBSERVATIONS: usize = 3;

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
    let target = SocketAddr::new(
        uri.host_str()
            .unwrap()
            .trim_matches(['[', ']'])
            .parse()
            .unwrap(),
        uri.port().unwrap(),
    );
    let observer = distinct_observer(target, bound_socket(target));
    assert!(
        observe_closed(target, observer)
            .await
            .expect("test infrastructure: closure observation"),
        "owned listener must be closed"
    );
}

async fn observe_closed(target: SocketAddr, mut observer: TcpSocket) -> std::io::Result<bool> {
    use std::io::{Error, ErrorKind};
    for _ in 0..MAX_CLOSURE_OBSERVATIONS {
        let connected = tokio::time::timeout(CLOSURE_STEP_TIMEOUT, observer.connect(target))
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "closure connection timed out"))?;
        let stream = match connected {
            Err(error) if error.kind() == ErrorKind::ConnectionRefused => return Ok(true),
            Err(error) => return Err(error),
            Ok(stream) => stream,
        };
        // A connect can complete while teardown is settling. Closed streams
        // permit another bounded observation, never successful closure by themselves.
        if !peer_closed(stream).await? {
            return Ok(false);
        }
        observer = distinct_observer(target, bound_socket(target));
    }
    Ok(false) // Even a live listener that immediately closes every stream must fail.
}

async fn peer_closed(mut stream: TcpStream) -> std::io::Result<bool> {
    use std::io::ErrorKind;
    match tokio::time::timeout(CLOSURE_STEP_TIMEOUT, stream.read(&mut [0; 1])).await {
        Ok(Ok(0)) => Ok(true),
        Ok(Err(error))
            if matches!(
                error.kind(),
                ErrorKind::ConnectionReset
                    | ErrorKind::ConnectionAborted
                    | ErrorKind::NotConnected
                    | ErrorKind::BrokenPipe
            ) =>
        {
            Ok(true)
        }
        Ok(Err(error)) => Err(error),
        Ok(Ok(_)) | Err(_) => Ok(false),
    }
}

fn bound_socket(target: SocketAddr) -> TcpSocket {
    let socket = if target.is_ipv4() {
        TcpSocket::new_v4()
    } else {
        TcpSocket::new_v6()
    }
    .expect("test infrastructure: create closure observer");
    socket
        .bind(SocketAddr::new(target.ip(), 0))
        .expect("test infrastructure: bind closure observer");
    socket
}

fn distinct_observer(target: SocketAddr, reserved: TcpSocket) -> TcpSocket {
    // Linux can connect a socket to itself if implicit source allocation reuses
    // the just-closed listener port. Reserve a distinct source before connecting.
    // Keep the colliding reservation alive until its replacement is bound.
    let observer = if reserved.local_addr().unwrap() == target {
        let replacement = bound_socket(target);
        drop(reserved);
        replacement
    } else {
        reserved
    };
    assert_ne!(
        observer.local_addr().unwrap(),
        target,
        "test infrastructure: observer cannot target itself"
    );
    observer
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn closure_observer_avoids_forced_source_collision_and_detects_a_live_listener() {
        for ip in ["127.0.0.1", "::1"] {
            let reserved = bound_socket(SocketAddr::new(ip.parse().unwrap(), 0));
            let target = reserved.local_addr().unwrap();
            let observer = distinct_observer(target, reserved);
            assert!(
                observe_closed(target, observer)
                    .await
                    .expect("test infrastructure: closed endpoint observation")
            );
            let listener = TcpListener::bind(SocketAddr::new(target.ip(), 0))
                .await
                .unwrap();
            let target = listener.local_addr().unwrap();
            let observer = distinct_observer(target, bound_socket(target));
            assert!(
                !observe_closed(target, observer)
                    .await
                    .expect("test infrastructure: live listener observation"),
                "live listener must never be reported closed"
            );
        }
    }

    #[tokio::test]
    async fn closure_observer_rejects_a_live_listener_that_immediately_closes_connections() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = listener.local_addr().unwrap();
        let (release, held) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            for _ in 0..MAX_CLOSURE_OBSERVATIONS {
                let (stream, _) = listener.accept().await.unwrap();
                drop(stream);
            }
            held.await.unwrap();
            drop(listener);
        });
        let observer = distinct_observer(target, bound_socket(target));
        assert!(
            !observe_closed(target, observer)
                .await
                .expect("test infrastructure: immediately closing live listener")
        );
        release.send(()).unwrap();
        task.await.unwrap();
    }
}
