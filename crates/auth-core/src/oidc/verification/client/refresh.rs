use super::{
    OidcClient, OidcClientCredential, OidcClientCredentials, OidcClientError, OidcClientResult,
    error::infrastructure, pending::now_us, response,
};
use crate::OidcTokenRequest;

impl OidcClient {
    /// Consume one native refresh generation. Never retry after an ambiguous
    /// result: reusing a spent generation revokes its entire server-side family.
    /// Store a successful replacement atomically in protected per-user storage.
    pub async fn refresh(
        &self,
        token: OidcClientCredential,
    ) -> OidcClientResult<OidcClientCredentials> {
        if !self.configuration.offline {
            return Err(OidcClientError::Configuration);
        }
        let _lease = self.work.lease().map_err(infrastructure)?;
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            let discovery = self
                .documents
                .discovery_when_admitted(self.context())
                .await
                .map_err(infrastructure)?;
            if !discovery
                .token_authentication_methods()
                .iter()
                .any(|v| v == "none")
            {
                return Err(OidcClientError::Configuration);
            }
            let url = url::Url::parse(discovery.token_endpoint())
                .map_err(|_| OidcClientError::Protocol)?;
            super::super::exchange::validate_token_endpoint(&url)
                .map_err(|_| OidcClientError::Protocol)?;
            let target = self
                .documents
                .resolve_target(url)
                .await
                .map_err(infrastructure)?;
            let request =
                OidcTokenRequest::refresh(&self.configuration.client.to_string(), token.expose());
            let started = now_us()?;
            let response = self
                .http
                .post(&target, &request)
                .await
                .map_err(infrastructure)?;
            let credentials = response::rotated(response, started)?;
            if now_us()? >= credentials.access_expires_us {
                return Err(OidcClientError::InvalidGrant);
            }
            Ok(credentials)
        })
        .await
        .map_err(|_| OidcClientError::Unavailable)?
    }
}
