use crate::{OAuthConnection, Result};
use async_trait::async_trait;
use std::{net::SocketAddr, time::Duration};

pub const MAX_OIDC_DOCUMENT_BYTES: usize = 65536;
pub const OIDC_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

pub struct OidcHttpResponse {
    pub status: u16,
    pub content_type: Option<String>,
    pub content_encoding: Option<String>,
    pub body: Vec<u8>,
    /// Remaining explicit HTTP max-age, after Age/no-store/no-cache handling.
    /// Unknown or non-cacheable responses use zero; core additionally caps it.
    pub cache_seconds: u64,
}

#[async_trait]
pub trait OidcConnectionRepository: Send + Sync {
    /// Recheck the exact live realm/connection/client/revision. No lock is held
    /// across network I/O. Metadata is not authority for a later identity commit.
    async fn check_oidc_connection(&self, connection: &OAuthConnection) -> Result<()>;
}

#[async_trait]
pub trait OidcHttp: Send + Sync {
    /// Bound returned answers; do not silently omit a disallowed/mixed answer.
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>>;
    /// Strict TLS/hostname verification, no redirects/proxies/re-resolution,
    /// streaming size/header/time bounds and no response/URL/error logging.
    async fn get(&self, target: &super::OidcTarget) -> Result<OidcHttpResponse>;
}
