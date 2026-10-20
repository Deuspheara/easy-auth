//! Count public GETs through unchanged production TLS. Token I/O is forbidden.
use async_trait::async_trait;
use auth_core::{
    Error, OidcHttp, OidcHttpResponse, OidcTarget, OidcTokenHttp, OidcTokenRequest,
    OidcTokenResponse, Result,
};
use easy_auth_server::OidcHttps;
use std::{
    net::SocketAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

#[derive(Default)]
pub(super) struct Network {
    https: OidcHttps,
    pub gets: AtomicUsize,
    pub blocked_posts: AtomicUsize,
}

#[async_trait]
impl OidcHttp for Network {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        self.https.resolve(host, port).await
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        self.gets.fetch_add(1, Ordering::SeqCst);
        self.https.get(target).await
    }
}

#[async_trait]
impl OidcTokenHttp for Network {
    async fn post(&self, _: &OidcTarget, _: &OidcTokenRequest) -> Result<OidcTokenResponse> {
        self.blocked_posts.fetch_add(1, Ordering::SeqCst);
        Err(Error::Unavailable)
    }
}
