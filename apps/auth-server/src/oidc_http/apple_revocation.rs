use super::super::post;
use super::{OidcHttps, client, response};
use async_trait::async_trait;
use auth_core::{
    AppleRevocationHttp, AppleRevocationRequest, AppleRevocationResponse, Error, OidcTarget, Result,
};

const MAX_REVOCATION_RESPONSE_BYTES: usize = 16 * 1024;

#[async_trait]
impl AppleRevocationHttp for OidcHttps {
    async fn revoke(
        &self,
        target: &OidcTarget,
        request: &AppleRevocationRequest,
    ) -> Result<AppleRevocationResponse> {
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
        send(&client, target.url(), target.addresses(), request.form())
            .await
            .map_err(|_| Error::Unavailable)
    }
}

// Private wire boundary shared with real-TLS tests. There is no public token or
// request constructor, alternate endpoint selector, or transport retry.
pub(super) async fn send(
    client: &reqwest::Client,
    url: &url::Url,
    addresses: &[std::net::SocketAddr],
    form: &str,
) -> std::result::Result<AppleRevocationResponse, response::Failure> {
    let response = post::send_form(client, url, form, None).await?;
    let response = response::read_profile(
        response,
        addresses,
        response::Profile {
            statuses: &[200, 400, 401],
            max_bytes: MAX_REVOCATION_RESPONSE_BYTES,
            allow_empty200: true,
            allow_jwk_type: false,
        },
    )
    .await?;
    AppleRevocationResponse::new(
        response.status,
        response.content_type,
        response.content_encoding,
        response.body,
    )
    .map_err(|_| response::Failure::Size)
}
