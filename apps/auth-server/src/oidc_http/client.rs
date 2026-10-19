use super::response::Failure;
use auth_core::OIDC_FETCH_TIMEOUT;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use url::Url;

const MAX_RESPONSE_HEADERS: usize = 32;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const READ_TIMEOUT: Duration = Duration::from_secs(2);

pub(super) fn builder(
    url: &Url,
    addresses: &[SocketAddr],
    roots: rustls::RootCertStore,
) -> Result<reqwest::ClientBuilder, Failure> {
    // Standard reviewed TLS policy, explicitly per client. Do not depend on or
    // replace an embedding application's process-global crypto provider.
    let tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|_| Failure::Configuration)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(reqwest::Client::builder()
        .tls_backend_preconfigured(tls)
        .https_only(true)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .referer(false)
        .connection_verbose(false)
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .no_zstd()
        .tls_sslkeylogfile(false)
        .http1_only()
        .http1_max_headers(MAX_RESPONSE_HEADERS)
        .pool_max_idle_per_host(0)
        .connect_timeout(CONNECT_TIMEOUT)
        .read_timeout(READ_TIMEOUT)
        .timeout(OIDC_FETCH_TIMEOUT)
        // Keep URL hostname for Host/SNI/certificate validation; pin the checked
        // addresses. The URL's effective port was validated by core, not this API.
        .resolve_to_addrs(url.host_str().ok_or(Failure::Configuration)?, addresses))
}
