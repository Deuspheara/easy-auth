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
    read_profile(
        response,
        addresses,
        Profile {
            statuses: &[200],
            max_bytes: MAX_OIDC_DOCUMENT_BYTES,
            allow_empty200: false,
            allow_jwk_type: true,
        },
    )
    .await
}

#[cfg(any(feature = "oidc-verification", feature = "oidc-client"))]
pub(super) async fn read_token(
    response: reqwest::Response,
    addresses: &[SocketAddr],
) -> Result<OidcHttpResponse, Failure> {
    read_profile(
        response,
        addresses,
        Profile {
            statuses: &[200, 400, 401],
            max_bytes: MAX_OIDC_DOCUMENT_BYTES,
            allow_empty200: false,
            allow_jwk_type: true,
        },
    )
    .await
}

// Trusted wire profiles are selected by concrete adapters, never by a request.
pub(super) struct Profile {
    pub statuses: &'static [u16],
    pub max_bytes: usize,
    pub allow_empty200: bool,
    pub allow_jwk_type: bool,
}

pub(super) async fn read_profile(
    mut response: reqwest::Response,
    addresses: &[SocketAddr],
    profile: Profile,
) -> Result<OidcHttpResponse, Failure> {
    let received = tokio::time::Instant::now();
    if !response
        .remote_addr()
        .is_some_and(|remote| addresses.contains(&remote))
    {
        return Err(Failure::Peer);
    }
    let status = response.status().as_u16();
    if !profile.statuses.contains(&status) {
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
    let type_count = response.headers().get_all(CONTENT_TYPE).iter().count();
    // Only the dedicated revocation profile permits an absent Content-Type,
    // and only for an actually empty200. Documents/token responses stay JSON.
    let optional_type = profile.allow_empty200 && status == 200;
    if type_count > 1 || (type_count == 0 && !optional_type) {
        return Err(Failure::ContentType);
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .map(|v| {
            v.to_str()
                .map(str::to_owned)
                .map_err(|_| Failure::ContentType)
        })
        .transpose()?;
    if let Some(value) = &content_type {
        let mime = value.split(';').next().unwrap_or("").trim();
        if !mime.eq_ignore_ascii_case("application/json")
            && (!profile.allow_jwk_type || !mime.eq_ignore_ascii_case("application/jwk-set+json"))
        {
            return Err(Failure::ContentType);
        }
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
        .is_some_and(|length| length > profile.max_bytes as u64)
    {
        return Err(Failure::Size);
    }
    let cache_seconds = cache_headers::seconds(response.headers());
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(network)? {
        if chunk.len() > profile.max_bytes - body.len() {
            return Err(Failure::Size);
        }
        body.extend_from_slice(&chunk);
    }
    if content_type.is_none() && !body.is_empty() {
        return Err(Failure::ContentType);
    }
    Ok(OidcHttpResponse {
        status,
        content_type,
        content_encoding,
        body,
        cache_seconds: std::time::Duration::from_secs(cache_seconds)
            .saturating_sub(received.elapsed())
            .as_secs(),
    })
}
