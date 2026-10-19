use super::{
    super::{
        client,
        response::{self, Failure},
    },
    tls_fixture::Fixture,
};
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

struct Trap(Arc<AtomicUsize>);
impl Resolve for Trap {
    fn resolve(&self, _: Name) -> Resolving {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async {
            Err::<Addrs, Box<dyn std::error::Error + Send + Sync>>(
                std::io::Error::other("test resolver must not run").into(),
            )
        })
    }
}

#[tokio::test]
async fn real_tls_uses_pinned_address_original_host_and_sni_without_resolving_again() {
    let f = Fixture::new().await;
    let url = f.url("/ok");
    let lookups = Arc::new(AtomicUsize::new(0));
    let client = client::builder(&url, &[f.address], f.roots())
        .unwrap()
        .dns_resolver(Arc::new(Trap(lookups.clone())))
        .build()
        .unwrap();
    let response = response::download(&client, &url, &[f.address])
        .await
        .unwrap();
    assert!(response.body == b"{}");
    assert!((119..=120).contains(&response.cache_seconds));
    assert_eq!(
        lookups.load(Ordering::SeqCst),
        0,
        "connector must not perform a second lookup"
    );
    let request = f.facts.requests.lock().unwrap()[0].clone();
    assert_eq!(request.0, "fixture.invalid");
    assert!(
        request
            .1
            .to_ascii_lowercase()
            .contains(&format!("host: fixture.invalid:{}", f.address.port()))
    );
    assert!(!request.1.to_ascii_lowercase().contains("authorization:"));
    assert!(!request.1.to_ascii_lowercase().contains("cookie:"));
    f.close().await;
}

#[tokio::test]
async fn unknown_root_and_wrong_hostname_fail_with_a_working_tls_positive_control() {
    let f = Fixture::new().await;
    let url = f.url("/ok");
    let valid = client::builder(&url, &[f.address], f.roots())
        .unwrap()
        .build()
        .unwrap();
    response::download(&valid, &url, &[f.address])
        .await
        .unwrap();
    let roots = rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let unknown = client::builder(&url, &[f.address], roots)
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        response::download(&unknown, &url, &[f.address]).await,
        Err(Failure::Certificate)
    ));
    let mut wrong = url.clone();
    wrong.set_host(Some("other.invalid")).unwrap();
    let wrong_client = client::builder(&wrong, &[f.address], f.roots())
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        response::download(&wrong_client, &wrong, &[f.address]).await,
        Err(Failure::Certificate)
    ));
    tokio::time::timeout(Duration::from_secs(2), async {
        while f.facts.failed_tls.load(Ordering::SeqCst) != 2 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("test infrastructure: both negative attempts reached the TLS fixture");
    assert_eq!(f.facts.requests.lock().unwrap().len(), 1);
    f.close().await;
}

#[tokio::test]
async fn broken_fixture_socket_is_not_misclassified_as_a_certificate_rejection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        drop(stream);
    });
    let url = url::Url::parse(&format!("https://fixture.invalid:{}/ok", address.port())).unwrap();
    let client = client::builder(&url, &[address], rustls::RootCertStore::empty())
        .unwrap()
        .build()
        .unwrap();
    assert!(matches!(
        response::download(&client, &url, &[address]).await,
        Err(Failure::Network)
    ));
    server
        .await
        .expect("test infrastructure: controlled reset was observed");
}

#[tokio::test]
async fn redirects_declared_chunked_oversize_encoding_headers_and_timeouts_have_exact_categories() {
    let f = Fixture::new().await;
    for (path, expected) in [
        ("/redirect", Failure::Status),
        ("/declared", Failure::Size),
        ("/chunked", Failure::Size),
        ("/encoding", Failure::Encoding),
        ("/headers", Failure::Headers),
        ("/html", Failure::ContentType),
        ("/duplicate-type", Failure::ContentType),
        ("/stall", Failure::Timeout),
    ] {
        let url = f.url(path);
        let builder = client::builder(&url, &[f.address], f.roots()).unwrap();
        let builder = if path == "/stall" {
            builder.timeout(Duration::from_millis(200))
        } else {
            builder
        };
        let client = builder.build().unwrap();
        let result = response::download(&client, &url, &[f.address]).await;
        assert_eq!(
            result.err(),
            Some(expected),
            "network/fixture failures must not count as policy rejection for {path}"
        );
    }
    assert_eq!(f.facts.requests.lock().unwrap().len(), 8);
    assert!(
        f.facts
            .requests
            .lock()
            .unwrap()
            .iter()
            .all(|(_, request)| !request.contains("/forbidden"))
    );
    f.close().await;
}

#[tokio::test]
async fn body_read_time_reduces_http_freshness_and_peer_mismatch_is_a_separate_failure() {
    let f = Fixture::new().await;
    let url = f.url("/age");
    let client = client::builder(&url, &[f.address], f.roots())
        .unwrap()
        .build()
        .unwrap();
    let response = response::download(&client, &url, &[f.address])
        .await
        .unwrap();
    assert!(response.body == b"{}");
    assert_eq!(
        response.cache_seconds, 0,
        "body read cannot restart max-age"
    );
    let url = f.url("/ok");
    let wrong_peer = "8.8.8.8:443".parse().unwrap();
    assert!(matches!(
        response::download(&client, &url, &[wrong_peer]).await,
        Err(Failure::Peer)
    ));
    assert_eq!(f.facts.requests.lock().unwrap().len(), 2);
    f.close().await;
}
