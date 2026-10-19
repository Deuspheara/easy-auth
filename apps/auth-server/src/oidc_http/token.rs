use super::super::post;
use super::{OidcHttps, client, response};
use async_trait::async_trait;
use auth_core::{Error, OidcTarget, OidcTokenHttp, OidcTokenRequest, OidcTokenResponse, Result};

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
        post::send(&client, target.url(), target.addresses(), request)
            .await
            .map_err(|_| Error::Unavailable)
    }
}
