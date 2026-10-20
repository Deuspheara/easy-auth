use super::super::GoogleDesktopError;
use super::setup::*;
use auth_core::Secret;
use std::{
    future::{pending, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[tokio::test]
async fn desktop_cancel_expiry_and_drop_close_the_owned_listener() {
    for mode in 0..3 {
        let listener = super::setup::listener().await;
        let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
        let state = Secret::generate().unwrap();
        match mode {
            0 => assert!(matches!(
                listener.receive(&state, expiry(), ready(())).await,
                Err(GoogleDesktopError::Cancelled)
            )),
            1 => assert!(matches!(
                listener.receive(&state, 0, pending()).await,
                Err(GoogleDesktopError::Expired)
            )),
            _ => drop(listener),
        }
        stopped(&uri).await;
    }
}

#[tokio::test]
async fn desktop_request_budget_and_body_bounds_do_not_capture_an_untrusted_callback() {
    let listener = super::setup::listener().await;
    let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
    let task = start(listener, Secret::generate().unwrap());
    for _ in 0..8 {
        assert!(
            send(&uri, &request(&uri, "state=invalid"))
                .await
                .starts_with("HTTP/1.1 400")
        );
    }
    assert!(matches!(
        task.await.unwrap(),
        Err(GoogleDesktopError::RequestLimit)
    ));
    stopped(&uri).await;
    let listener = super::setup::listener().await;
    let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
    let state = Secret::generate().unwrap();
    let query = format!("{}&prompt={}", query(&state, None), "a".repeat(2049));
    let task = start(listener, state);
    assert!(
        send(&uri, &request(&uri, &query))
            .await
            .starts_with("HTTP/1.1 400")
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    stopped(&uri).await;
}

#[tokio::test]
async fn desktop_cancellation_closes_a_partial_connection_without_detached_tasks() {
    let listener = super::setup::listener().await;
    let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
    let state = Secret::generate().unwrap();
    let (cancel, cancelled) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        listener
            .receive(&state, expiry(), async {
                let _ = cancelled.await;
            })
            .await
    });
    let mut stream = TcpStream::connect(("127.0.0.1", uri.port().unwrap()))
        .await
        .unwrap();
    stream
        .write_all(b"GET /owned/return HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    cancel.send(()).unwrap();
    assert!(matches!(
        task.await.unwrap(),
        Err(GoogleDesktopError::Cancelled)
    ));
    let mut bytes = Vec::new();
    let result = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut bytes))
        .await
        .unwrap();
    assert!(
        result.is_err() || bytes.is_empty(),
        "partial connection is closed without authority"
    );
    stopped(&uri).await;
}

#[tokio::test]
async fn desktop_slow_header_deadline_releases_connection_and_preserves_a_valid_return() {
    let listener = super::setup::listener().await;
    let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
    let state = Secret::generate().unwrap();
    let valid = request(&uri, &query(&state, None));
    let task = start(listener, state);
    let mut stream = TcpStream::connect(("127.0.0.1", uri.port().unwrap()))
        .await
        .unwrap();
    stream
        .write_all(b"GET /owned/return HTTP/1.1\r\nHost:")
        .await
        .unwrap();
    let mut bytes = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut bytes))
        .await
        .expect("test infrastructure: actual HTTP header timeout must close stream")
        .unwrap();
    assert!(
        !task.is_finished(),
        "slow untrusted input does not complete operation"
    );
    assert!(send(&uri, &valid).await.starts_with("HTTP/1.1 200"));
    task.await.unwrap().unwrap();
    stopped(&uri).await;
}

#[tokio::test]
async fn desktop_http_header_count_and_buffer_limits_preserve_valid_control() {
    for count_limit in [true, false] {
        let listener = super::setup::listener().await;
        let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
        let state = Secret::generate().unwrap();
        let valid = request(&uri, &query(&state, None));
        let headers = if count_limit {
            (0..33)
                .map(|n| format!("X-Owned-{n}: a\r\n"))
                .collect::<String>()
        } else {
            format!("X-Owned: {}\r\n", "a".repeat(18 * 1024))
        };
        let invalid = valid.replace("\r\n\r\n", &format!("\r\n{headers}\r\n"));
        let task = start(listener, state);
        assert!(send(&uri, &invalid).await.starts_with("HTTP/1.1 431"));
        assert!(!task.is_finished());
        assert!(send(&uri, &valid).await.starts_with("HTTP/1.1 200"));
        task.await.unwrap().unwrap();
        stopped(&uri).await;
    }
}
