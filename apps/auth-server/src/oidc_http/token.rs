use super::{OidcHttps, client, response};
use async_trait::async_trait;
use auth_core::{Error, OidcTarget, OidcTokenHttp, OidcTokenRequest, OidcTokenResponse, Result};
use reqwest::header::{ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HeaderValue, PRAGMA};

#[async_trait]
impl OidcTokenHttp for OidcHttps {
    async fn post(
        &self,
        target: &OidcTarget,
        request: &OidcTokenRequest,
    ) -> Result<OidcTokenResponse> {
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
        send(&client, target.url(), target.addresses(), request)
            .await
            .map_err(|_| Error::Unavailable)
    }
}

pub(super) async fn send(
    client: &reqwest::Client,
    url: &url::Url,
    addresses: &[std::net::SocketAddr],
    request: &OidcTokenRequest,
) -> std::result::Result<OidcTokenResponse, response::Failure> {
    let mut outbound = client
        .post(url.clone())
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(ACCEPT, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header(PRAGMA, "no-cache")
        .body(request.form().as_bytes().to_vec());
    if let Some(value) = request.authorization() {
        let mut header =
            HeaderValue::from_str(value).map_err(|_| response::Failure::Configuration)?;
        header.set_sensitive(true);
        outbound = outbound.header(AUTHORIZATION, header);
    }
    // No retry/redirect/cookie/proxy branch; the same checked target, normal
    // hostname/TLS validation and bounded response reader protect the POST.
    let response = outbound.send().await.map_err(response::network)?;
    let response = response::read_token(response, addresses).await?;
    OidcTokenResponse::new(
        response.status,
        response.content_type,
        response.content_encoding,
        response.body,
    )
    .map_err(|_| response::Failure::Size)
}
