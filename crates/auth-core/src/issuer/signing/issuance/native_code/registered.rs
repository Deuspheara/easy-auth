use super::service::TOKEN_OPERATION_TIMEOUT;
use super::{IssuerNativeTokenIssuer, IssuerNativeTokens};
use crate::{
    IssuerClientAuthentication, IssuerPkceVerifier, IssuerRedirectProfile, IssuerTokenError,
    IssuerTokenIssuer, IssuerTokenResult, IssuerTokens, Secret,
};
use std::sync::Arc;

/// Committed credentials from exactly one registered code profile. This is not
/// a proof constructor, local session or retry across failed grant operations.
pub enum IssuerClientTokens {
    Online(IssuerTokens),
    Native(IssuerNativeTokens),
}
impl IssuerNativeTokenIssuer {
    /// Dispatch from one admitted current registration snapshot. Both concrete
    /// operations retain their original policy/PKCE/source/code/signing checks
    /// and final transaction authentication; a failed branch is never retried.
    pub async fn exchange_registered(
        &self,
        online: &IssuerTokenIssuer,
        authentication: &IssuerClientAuthentication,
        code: &Secret,
        redirect_uri: &str,
        pkce: &IssuerPkceVerifier,
        source: &str,
    ) -> IssuerTokenResult<IssuerClientTokens> {
        if online.authority() != self.authority() || !Arc::ptr_eq(&online.engine, &self.engine) {
            return Err(IssuerTokenError::Unavailable);
        }
        let lease = self.engine.acquire()?;
        tokio::time::timeout(TOKEN_OPERATION_TIMEOUT, async {
            let client = self
                .authorization
                .client_for_token_operation(authentication, source)
                .await?;
            if client.redirect_profile() == IssuerRedirectProfile::NativeRefreshLoopback {
                self.issue_admitted(&client, authentication, code, redirect_uri, pkce, lease)
                    .await
                    .map(IssuerClientTokens::Native)
            } else {
                online
                    .issue_admitted(&client, authentication, code, redirect_uri, pkce, lease)
                    .await
                    .map(IssuerClientTokens::Online)
            }
        })
        .await
        .map_err(|_| IssuerTokenError::Unavailable)?
    }
}
