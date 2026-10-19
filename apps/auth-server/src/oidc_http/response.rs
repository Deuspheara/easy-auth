use super::cache_headers;
use auth_core::{MAX_OIDC_DOCUMENT_BYTES, OidcHttpResponse};
use reqwest::{
    Client,
    header::{CONTENT_ENCODING, CONTENT_TYPE},
};
use std::error::Error as StdError;
use std::net::SocketAddr;
use url::Url;

const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;
const MAX_ERROR_CAUSES: usize = 16;

// Finite private categories let regressions distinguish intended policy rejection
// from a broken TLS fixture/network. No URL, response body or raw error is retained.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum Failure {
    Configuration,
    Network,
    Certificate,
    Timeout,
    Peer,
    Status,
    Headers,
    Encoding,
    ContentType,
    Size,
}

pub(super) fn network(error: reqwest::Error) -> Failure {
    if error.is_timeout() {
        return Failure::Timeout;
    }
    // Inspect typed causes only, never messages/URLs. Certificate negatives must
    // not pass because a fixture socket failed before verification was reached.
    let mut cause: Option<&(dyn StdError + 'static)> = Some(&error);
    for _ in 0..MAX_ERROR_CAUSES {
        let Some(current) = cause else {
            break;
        };
        if matches!(
            current.downcast_ref::<rustls::Error>(),
            Some(rustls::Error::InvalidCertificate(_))
        ) {
            return Failure::Certificate;
        }
        // io::Error::source can skip the boxed error itself. Inspect its typed
        // payload before following another source, without formatting messages.
        cause = if let Some(io) = current.downcast_ref::<std::io::Error>() {
            io.get_ref()
                .map(|inner| inner as &(dyn StdError + 'static))
                .or_else(|| current.source())
        } else {
            current.source()
        };
    }
    Failure::Network
}

pub(super) async fn download(
    client: &Client,
    url: &Url,
    addresses: &[SocketAddr],
) -> Result<OidcHttpResponse, Failure> {
    let response = client.get(url.clone()).send().await.map_err(network)?;
    read(response, addresses).await
}

/// Shared bounded response boundary for configured document and token requests.
/// Callers own request construction, credentials and the whole request deadline.
pub(super) async fn read(
    response: reqwest::Response,
    addresses: &[SocketAddr],
) -> Result<OidcHttpResponse, Failure> {
    read_statuses(response, addresses, &[200]).await
}

#[cfg(feature = "oidc-verification")]
pub(super) async fn read_token(
    response: reqwest::Response,
    addresses: &[SocketAddr],
) -> Result<OidcHttpResponse, Failure> {
    read_statuses(response, addresses, &[200, 400, 401]).await
}

async fn read_statuses(
    mut response: reqwest::Response,
    addresses: &[SocketAddr],
    statuses: &[u16],
) -> Result<OidcHttpResponse, Failure> {
    let received = tokio::time::Instant::now();
    if !response
        .remote_addr()
        .is_some_and(|remote| addresses.contains(&remote))
    {
        return Err(Failure::Peer);
    }
    let status = response.status().as_u16();
    if !statuses.contains(&status) {
        return Err(Failure::Status);
    }
    if response
        .headers()
        .iter()
        .map(|(name, value)| name.as_str().len() + value.as_bytes().len())
        .sum::<usize>()
        > MAX_RESPONSE_HEADER_BYTES
    {
        return Err(Failure::Headers);
    }
    if response.headers().get_all(CONTENT_TYPE).iter().count() != 1 {
        return Err(Failure::ContentType);
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or(Failure::ContentType)?
        .to_owned();
    let mime = content_type.split(';').next().unwrap_or("").trim();
    if !mime.eq_ignore_ascii_case("application/json")
        && !mime.eq_ignore_ascii_case("application/jwk-set+json")
    {
        return Err(Failure::ContentType);
    }
    if response.headers().get_all(CONTENT_ENCODING).iter().count() > 1 {
        return Err(Failure::Encoding);
    }
    let content_encoding = match response.headers().get(CONTENT_ENCODING) {
        None => None,
        Some(value) => Some(value.to_str().map_err(|_| Failure::Encoding)?.to_owned()),
    };
    if content_encoding
        .as_deref()
        .is_some_and(|value| !value.trim().eq_ignore_ascii_case("identity"))
    {
        return Err(Failure::Encoding);
    }
    if response
        .content_length()
        .is_some_and(|length| length > MAX_OIDC_DOCUMENT_BYTES as u64)
    {
        return Err(Failure::Size);
    }
    let cache_seconds = cache_headers::seconds(response.headers());
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network)? {
        if chunk.len() > MAX_OIDC_DOCUMENT_BYTES - body.len() {
            return Err(Failure::Size);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(OidcHttpResponse {
        status,
        content_type: Some(content_type),
        content_encoding,
        body,
        cache_seconds: std::time::Duration::from_secs(cache_seconds)
            .saturating_sub(received.elapsed())
            .as_secs(),
    })
}
