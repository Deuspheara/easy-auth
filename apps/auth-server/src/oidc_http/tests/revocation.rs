use super::{
    super::{apple_revocation, client, response::Failure},
    tls_fixture::Fixture,
};
use auth_core::Secret;
use std::time::Duration;

async fn send(f: &Fixture, path: &str) -> Result<auth_core::AppleRevocationResponse, Failure> {
    let url = f.url(path);
    let builder = client::builder(&url, &[f.address], f.roots()).unwrap();
    let client = if path == "/revoke/stall" {
        builder.timeout(Duration::from_millis(200))
    } else {
        builder
    }
    .build()
    .unwrap();
    // Wire-only transport test: actual worker fixtures separately verify the
    // protected ES256 client secret, captured grant, source and token-type hint.
    let token = Secret::generate().unwrap();
    let secret = Secret::generate().unwrap();
    let form = url::form_urlencoded::Serializer::new(String::new())
        .append_pair("client_id", "owned-tls-client")
        .append_pair("client_secret", secret.expose())
        .append_pair("token", token.expose())
        .append_pair("token_type_hint", "refresh_token")
        .finish();
    apple_revocation::send(&client, &url, &[f.address], &form).await
}

#[tokio::test]
async fn real_tls_revocation_accepts_empty200_and_bounded_errors_without_cookies_or_retry() {
    let f = Fixture::new().await;
    for path in [
        "/revoke/empty",
        "/revoke/nonempty",
        "/revoke/error",
        "/revoke/config",
    ] {
        let response = send(&f, path).await.expect("working TLS transport control");
        assert_eq!(
            format!("{response:?}"),
            "AppleRevocationResponse([REDACTED])"
        );
        // Receiving a bounded body confers no confirmation. Core verification
        // rejects nonempty200 and classifies error bodies before repository ACK.
    }
    {
        let requests = f.facts.requests.lock().unwrap();
        let bodies = f.facts.bodies.lock().unwrap();
        assert_eq!(requests.len(), 4);
        assert_eq!(bodies.len(), 4);
        for ((sni, head), body) in requests.iter().zip(bodies.iter()) {
            assert_eq!(sni, "fixture.invalid");
            assert!(head.starts_with("POST /revoke/"));
            let head = head.to_ascii_lowercase();
            assert!(head.contains("content-type: application/x-www-form-urlencoded\r\n"));
            assert!(head.contains("cache-control: no-store\r\n"));
            assert!(head.contains("pragma: no-cache\r\n"));
            assert!(!head.contains("cookie:"));
            assert!(!head.contains("authorization:"));
            let fields: Vec<_> = url::form_urlencoded::parse(body).collect();
            assert_eq!(fields.len(), 4);
            assert!(
                fields
                    .iter()
                    .any(|(k, v)| k == "token_type_hint" && v == "refresh_token")
            );
        }
    }
    f.close().await;
}

#[tokio::test]
async fn real_tls_revocation_rejects_bad_envelopes_and_smaller_body_limit_without_retry() {
    let f = Fixture::new().await;
    for (path, expected) in [
        ("/revoke/missing-type", Failure::ContentType),
        ("/revoke/duplicate-type", Failure::ContentType),
        ("/revoke/html", Failure::ContentType),
        ("/revoke/encoding", Failure::Encoding),
        ("/revoke/duplicate-encoding", Failure::Encoding),
        ("/revoke/redirect", Failure::Status),
        ("/revoke/large", Failure::Size),
        ("/revoke/chunked", Failure::Size),
        ("/revoke/stall", Failure::Timeout),
    ] {
        assert_eq!(
            send(&f, path).await.err(),
            Some(expected),
            "{path} finite policy failure"
        );
    }
    assert_eq!(f.facts.requests.lock().unwrap().len(), 9);
    assert!(
        !f.facts
            .requests
            .lock()
            .unwrap()
            .iter()
            .any(|(_, h)| h.contains("/forbidden"))
    );
    f.close().await;
}

#[tokio::test]
async fn real_tls_revocation_requires_trusted_certificate_and_original_hostname() {
    let f = Fixture::new().await;
    for trusted in [false, true] {
        let mut url = f.url("/revoke/empty");
        let roots = if trusted {
            url.set_host(Some("wrong.invalid")).unwrap();
            f.roots()
        } else {
            rustls::RootCertStore::empty()
        };
        let client = client::builder(&url, &[f.address], roots)
            .unwrap()
            .build()
            .unwrap();
        let result =
            apple_revocation::send(&client, &url, &[f.address], "protected-owned-fixture").await;
        assert_eq!(result.err(), Some(Failure::Certificate));
    }
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.facts.failed_tls.load(std::sync::atomic::Ordering::SeqCst) != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("both negative requests reached owned TLS fixture");
    assert!(f.facts.requests.lock().unwrap().is_empty());
    f.close().await;
}
