use super::{
    super::{OidcHttps, client, response},
    tls_fixture::Fixture,
};
use std::{
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

#[tokio::test(flavor = "multi_thread")]
async fn cold_client_ignores_process_proxy_without_global_tls_state() {
    const CHILD: &str = "EASY_AUTH_OIDC_COLD_TLS_CHILD";
    if std::env::var_os(CHILD).is_some() {
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        let f = Fixture::new().await;
        let url = f.url("/ok");
        let http = OidcHttps::new();
        client::builder(&url, &[f.address], http.roots)
            .unwrap()
            .build()
            .unwrap();
        let client = client::builder(&url, &[f.address], f.roots())
            .unwrap()
            .build()
            .unwrap();
        response::download(&client, &url, &[f.address])
            .await
            .unwrap();
        assert!(rustls::crypto::CryptoProvider::get_default().is_none());
        assert_eq!(f.facts.requests.lock().unwrap().len(), 1);
        f.close().await;
        return;
    }
    // Scope proxy variables to a child only; never mutate the embedding process's
    // environment. The endpoint is an exact owned listener, not a user's proxy.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy = format!("http://{}", listener.local_addr().unwrap());
    let hits = Arc::new(AtomicUsize::new(0));
    let observer = {
        let hits = hits.clone();
        tokio::spawn(async move {
            while let Ok((_, _)) = listener.accept().await {
                hits.fetch_add(1, Ordering::SeqCst);
            }
        })
    };
    let output=tokio::task::spawn_blocking(move || {
        let mut command=Command::new(std::env::current_exe().unwrap());
        command.args(["--exact","oidc_http::transport::tests::cold::cold_client_ignores_process_proxy_without_global_tls_state","--nocapture"])
            .env(CHILD,"1").env_remove("NO_PROXY").env_remove("no_proxy");
        for name in ["HTTPS_PROXY","https_proxy","HTTP_PROXY","http_proxy","ALL_PROXY","all_proxy"] {
            command.env(name,&proxy);
        }
        command.output().expect("test infrastructure: cold child process")
    }).await.unwrap();
    observer.abort();
    let _ = observer.await;
    assert!(
        output.status.success(),
        "cold child TLS/proxy regression failed"
    );
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("1 passed"),
        "test infrastructure: exact child case ran"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "metadata must not use an environment proxy"
    );
}
