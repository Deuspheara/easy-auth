use super::super::{GoogleDesktopError, GoogleDesktopListener};
use super::setup::*;
use auth_core::Secret;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

#[tokio::test]
async fn desktop_listener_owns_exact_ipv4_and_ipv6_return_and_never_echoes_proof() {
    for ip in [
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ] {
        let listener = GoogleDesktopListener::bind(ip, "/owned/return")
            .await
            .unwrap();
        let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
        assert_ne!(uri.port(), Some(0));
        assert_eq!(uri.scheme(), "http");
        let state = Secret::generate().unwrap();
        let query = query(&state, None);
        let secret = state.expose().to_owned();
        let task = start(listener, state);
        let response = send(&uri, &request(&uri, &query)).await;
        assert!(response.starts_with("HTTP/1.1 200"));
        for forbidden in [
            secret.as_str(),
            "owned-private-code",
            "private-foreign-detail",
            "set-cookie:",
        ] {
            assert!(
                !response.contains(forbidden),
                "no proof/credential/cookie in fixed response"
            );
        }
        for header in [
            "cache-control: no-store",
            "referrer-policy: no-referrer",
            "content-security-policy:",
            "connection: close",
            "x-frame-options: DENY",
        ] {
            assert!(response.contains(header));
        }
        assert!(response.contains("history.replaceState(null, \"\", location.pathname);"));
        let received = tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert_eq!(format!("{received:?}"), "GoogleDesktopCallback([REDACTED])");
        stopped(&uri).await;
    }
}

#[tokio::test]
async fn desktop_rejects_wildcard_alias_and_malformed_return_configuration() {
    for ip in ["0.0.0.0", "127.0.0.2", "::", "192.0.2.1"] {
        assert!(matches!(
            GoogleDesktopListener::bind(ip.parse().unwrap(), "/return").await,
            Err(GoogleDesktopError::InvalidInput)
        ));
    }
    for path in [
        "/",
        "relative",
        "//other",
        "/return?code=injected",
        "/return#fragment",
        "/a/../return",
        "/return%2Falias",
        "/with space",
    ] {
        assert!(matches!(
            GoogleDesktopListener::bind(IpAddr::V4(Ipv4Addr::LOCALHOST), path).await,
            Err(GoogleDesktopError::InvalidInput)
        ));
    }
}

#[tokio::test]
async fn desktop_http_negatives_do_not_capture_or_consume_the_valid_return() {
    for dimension in 0..11 {
        let listener = listener().await;
        let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
        let state = Secret::generate().unwrap();
        let query = query(&state, None);
        let valid = request(&uri, &query);
        let bad = match dimension {
            0 => valid.replacen("GET ", "POST ", 1),
            1 => valid.replace(uri.authority(), "localhost:1234"),
            2 => valid.replacen(uri.path(), "/wrong", 1),
            3 => valid.replace(" HTTP/1.1", " HTTP/1.0"),
            4 => valid.replace("owned-private-code", "%FF"),
            5 => valid.replace("owned-private-code", "one&code=two"),
            6 => valid.replace(
                "https%3A%2F%2Faccounts.google.com",
                "https%3A%2F%2Fother.example",
            ),
            7 => valid.replace(state.expose(), Secret::generate().unwrap().expose()),
            8 => valid.replace("\r\n\r\n", "\r\nContent-Length: 1\r\n\r\nx"),
            9 => valid.replace(
                "\r\n\r\n",
                "\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            ),
            _ => valid.replacen(
                uri.path(),
                &format!("http://{}{}", uri.authority(), uri.path()),
                1,
            ),
        };
        let task = start(listener, state);
        let response = send(&uri, &bad).await;
        assert!(
            response.starts_with("HTTP/1.1 400") || response.starts_with("HTTP/1.0 400"),
            "wire dimension {dimension}: invalid request must receive status400"
        );
        assert!(
            !task.is_finished(),
            "invalid delivery cannot complete operation"
        );
        assert!(!response.contains("owned-private-code"));
        assert!(send(&uri, &valid).await.starts_with("HTTP/1.1 200"));
        task.await.unwrap().unwrap();
        stopped(&uri).await;
    }
}

#[tokio::test]
async fn desktop_denial_and_provider_failure_are_received_without_reflecting_foreign_details() {
    for error in ["access_denied", "server_error"] {
        let listener = listener().await;
        let uri = url::Url::parse(listener.redirect().as_str()).unwrap();
        let state = Secret::generate().unwrap();
        let query = query(&state, Some(error));
        let task = start(listener, state);
        let response = send(&uri, &request(&uri, &query)).await;
        assert!(response.starts_with("HTTP/1.1 200"));
        assert!(!response.contains(error));
        assert!(!response.contains("private-foreign-detail"));
        task.await.unwrap().unwrap();
        stopped(&uri).await;
    }
}
