use super::{client, response};

use async_trait::async_trait;
use auth_core::{Error, MAX_OIDC_DNS_ANSWERS, OidcHttp, OidcHttpResponse, OidcTarget, Result};
use std::{
    net::{SocketAddr, ToSocketAddrs},
    sync::Arc,
};
use tokio::sync::Semaphore;

const MAX_IN_FLIGHT_OPERATIONS: usize = 4;

#[cfg(any(feature = "oidc-verification", feature = "oidc-client"))]
#[path = "token.rs"]
mod token;

/// Shared concrete metadata transport. Clone/share one adapter across configured
/// connections; no HTTP API, provider credential or permissive development mode.
#[derive(Clone)]
pub struct OidcHttps {
    roots: rustls::RootCertStore,
    operations: Arc<Semaphore>,
}
impl Default for OidcHttps {
    fn default() -> Self {
        Self::new()
    }
}
impl OidcHttps {
    pub fn new() -> Self {
        Self {
            roots: rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned()),
            operations: Arc::new(Semaphore::new(MAX_IN_FLIGHT_OPERATIONS)),
        }
    }

    async fn lookup<F>(&self, resolve: F) -> Result<Vec<SocketAddr>>
    where
        F: FnOnce() -> std::io::Result<Vec<SocketAddr>> + Send + 'static,
    {
        let permit = self
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited)?;
        // Native getaddrinfo cannot be cancelled. The blocking job keeps its
        // permit even if its async caller times out, bounding detached DNS work.
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            resolve()
        })
        .await
        .map_err(|_| Error::Unavailable)?
        .map_err(|_| Error::Unavailable)
    }
}

#[async_trait]
impl OidcHttp for OidcHttps {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        let host = host.to_owned();
        self.lookup(move || {
            (host.as_str(), port)
                .to_socket_addrs()
                .map(|answers| answers.take(MAX_OIDC_DNS_ANSWERS + 1).collect())
        })
        .await
    }
    async fn get(&self, target: &OidcTarget) -> Result<OidcHttpResponse> {
        let _permit = self
            .operations
            .clone()
            .try_acquire_owned()
            .map_err(|_| Error::RateLimited)?;
        let client = client::builder(target.url(), target.addresses(), self.roots.clone())
            .and_then(|builder| {
                builder
                    .build()
                    .map_err(|_| response::Failure::Configuration)
            })
            .map_err(|_| Error::Unavailable)?;
        response::download(&client, target.url(), target.addresses())
            .await
            .map_err(|_| Error::Unavailable)
    }
}

#[cfg(test)]
#[path = "tests/mod.rs"]
mod tests;
