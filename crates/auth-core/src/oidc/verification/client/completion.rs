use super::super::{
    OidcSigningAlgorithm, OidcVerificationPolicy,
    claims::{ClaimContext, MAX_TOKEN_AGE_SECONDS},
    input,
    work::{self, Attempt},
};
use super::{
    OidcClient, OidcClientAuthorization, OidcClientError, OidcClientResult, callback,
    error::infrastructure,
    pending::now_us,
    tokens::{OidcClientIdentity, OidcClientTokens},
};
use crate::{Error, OidcDiscovery, OidcIdToken, OidcTokenRequest};
use std::sync::Arc;
use tokio::sync::OwnedSemaphorePermit;

impl OidcClient {
    /// Consumes this privately retained operation on every result. Codes are sent
    /// once: failed/ambiguous exchanges require a new authorization operation.
    pub async fn complete(
        &self,
        pending: OidcClientAuthorization,
        actual_callback: &str,
    ) -> OidcClientResult<OidcClientTokens> {
        let lease = self.work.lease().map_err(infrastructure)?;
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            pending.check(self.id)?;
            let code = callback::code(&self.configuration, &pending, actual_callback)?;
            let discovery = self
                .documents
                .discovery_when_admitted(self.context())
                .await
                .map_err(infrastructure)?;
            if !discovery.supports_s256()
                || !discovery
                    .token_authentication_methods()
                    .iter()
                    .any(|v| v == self.configuration.authentication.method())
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
            pending.check(self.id)?;
            let request = OidcTokenRequest::for_client(
                &self.configuration.client.to_string(),
                &self.configuration.redirect,
                &pending.pkce,
                code,
                &self.configuration.authentication,
            );
            let started = now_us()?;
            let response = self
                .http
                .post(&target, &request)
                .await
                .map_err(infrastructure)?;
            pending.check(self.id)?;
            let initial = super::response::initial(response, self.configuration.offline, started)?;
            let identity = tokio::time::timeout(
                std::time::Duration::from_secs(15),
                self.identity(&pending, initial.id, &discovery, lease),
            )
            .await
            .map_err(|_| OidcClientError::Unavailable)??;
            if now_us()? >= initial.credentials.access_expires_us {
                return Err(OidcClientError::InvalidGrant);
            }
            Ok(OidcClientTokens {
                identity,
                credentials: initial.credentials,
            })
        })
        .await
        .map_err(|_| OidcClientError::Unavailable)?
    }
    async fn identity(
        &self,
        pending: &OidcClientAuthorization,
        token: OidcIdToken,
        discovery: &OidcDiscovery,
        lease: Arc<OwnedSemaphorePermit>,
    ) -> OidcClientResult<OidcClientIdentity> {
        let policy = OidcVerificationPolicy::new(&[OidcSigningAlgorithm::RS256], &[])
            .map_err(infrastructure)?;
        let header = input::header(&token.0).map_err(|_| OidcClientError::InvalidToken)?;
        if header.alg != OidcSigningAlgorithm::RS256 {
            return Err(OidcClientError::InvalidToken);
        }
        let observed = self
            .documents
            .keys_when_admitted(self.context(), discovery)
            .await
            .map_err(infrastructure)?;
        let claims = match work::attempt(&token, observed.clone(), lease.clone())
            .await
            .map_err(verification_error)?
        {
            Attempt::Claims(claims) => claims,
            Attempt::UnknownKey => {
                let current = self
                    .documents
                    .keys_from_discovery(self.context(), discovery, Some(&observed))
                    .await
                    .map_err(infrastructure)?;
                match work::attempt(&token, current, lease)
                    .await
                    .map_err(verification_error)?
                {
                    Attempt::Claims(claims) => claims,
                    Attempt::UnknownKey => return Err(OidcClientError::InvalidToken),
                }
            }
        };
        pending.check(self.id)?;
        claims
            .validate_context(
                &ClaimContext {
                    issuer: &self.configuration.issuer,
                    client: &self.configuration.client.to_string(),
                    nonce: &pending.nonce,
                    expires_us: pending.expires_us,
                },
                &policy,
                now_us()?,
            )
            .map_err(verification_error)?;
        let cap = (i128::from(claims.exp) * 1_000_000)
            .min((i128::from(claims.iat) + i128::from(MAX_TOKEN_AGE_SECONDS)) * 1_000_000)
            .min(i128::from(pending.expires_us));
        Ok(OidcClientIdentity {
            issuer: self.configuration.issuer.clone(),
            client: self.configuration.client,
            subject: claims.sub.clone(),
            issued_at: claims.iat,
            authenticated_at: claims.auth_time,
            expires_us: cap.try_into().map_err(|_| OidcClientError::Unavailable)?,
        })
    }
}
fn verification_error(error: Error) -> OidcClientError {
    match error {
        Error::Unauthorized | Error::InvalidInput => OidcClientError::InvalidToken,
        _ => infrastructure(error),
    }
}
