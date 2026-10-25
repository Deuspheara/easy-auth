use super::response;
use auth_core::{OidcTokenRequest, OidcTokenResponse};
use reqwest::header::{ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE, HeaderValue, PRAGMA};

pub(super) async fn send(
    client: &reqwest::Client,
    url: &url::Url,
    addresses: &[std::net::SocketAddr],
    request: &OidcTokenRequest,
) -> std::result::Result<OidcTokenResponse, response::Failure> {
    let response = send_form(client, url, request.form(), request.authorization()).await?;
    let response = response::read_token(response, addresses).await?;
    OidcTokenResponse::new(
        response.status,
        response.content_type,
        response.content_encoding,
        response.body,
    )
    .map_err(|_| response::Failure::Size)
}

/// The caller selects the response profile; credential transport policy is shared.
pub(super) async fn send_form(
    client: &reqwest::Client,
    url: &url::Url,
    form: &str,
    authorization: Option<&str>,
) -> std::result::Result<reqwest::Response, response::Failure> {
    let mut outbound = client
        .post(url.clone())
        .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
        .header(ACCEPT, "application/json")
        .header(CACHE_CONTROL, "no-store")
        .header(PRAGMA, "no-cache")
        .body(form.as_bytes().to_vec());
    if let Some(value) = authorization {
        let mut header =
            HeaderValue::from_str(value).map_err(|_| response::Failure::Configuration)?;
        header.set_sensitive(true);
        outbound = outbound.header(AUTHORIZATION, header);
    }
    // No retry/redirect/cookie/proxy branch; the same checked target, normal
    // hostname/TLS validation and bounded response reader protect the POST.
    outbound.send().await.map_err(response::network)
}
