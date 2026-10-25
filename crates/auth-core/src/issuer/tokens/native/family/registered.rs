use super::IssuerNativeRefresh;
use super::service::NATIVE_OPERATION_TIMEOUT;
use crate::{
    IssuerClientAuthentication, IssuerPresentedToken, IssuerRedirectProfile, IssuerTokenError,
    IssuerTokenManagement, IssuerTokenResult,
};

impl IssuerNativeRefresh {
    /// One source admission selects a registered reduction path, never a token
    /// hint or cookie. Current credentials/scoped possession remain mandatory
    /// in the selected transaction, including unknown/idempotent cleanup.
    pub async fn revoke_registered(
        &self,
        online: &IssuerTokenManagement,
        authentication: &IssuerClientAuthentication,
        token: &IssuerPresentedToken,
        source: &str,
    ) -> IssuerTokenResult<()> {
        if online.authority() != self.authority() {
            return Err(IssuerTokenError::Unavailable);
        }
        tokio::time::timeout(NATIVE_OPERATION_TIMEOUT, async {
            let client = self
                .authorization
                .client_for_token_operation(authentication, source)
                .await?;
            if client.redirect_profile() == IssuerRedirectProfile::NativeRefreshLoopback {
                self.revoke_admitted(&client, authentication, token).await
            } else {
                online.revoke_admitted(&client, authentication, token).await
            }
        })
        .await
        .map_err(|_| IssuerTokenError::Unavailable)?
    }
}
