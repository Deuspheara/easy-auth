use super::{
    IssuerAuthority, IssuerAuthorizationInput, IssuerAuthorizationPreview,
    IssuerAuthorizationRepository, IssuerAuthorizationRequest, IssuerAuthorizationReturn,
    IssuerAuthorizationStart, IssuerCodeRedemption, IssuerConsentProof, IssuerPkceVerifier,
    IssuerRedeemedCode, IssuerTokenError, IssuerTokenResult, request, response,
};
use crate::{IssuerClientAuthentication, Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

pub struct IssuerAuthorization {
    authority: IssuerAuthority,
    repository: Arc<dyn IssuerAuthorizationRepository>,
}
impl IssuerAuthorization {
    pub fn new(
        authority: IssuerAuthority,
        repository: Arc<dyn IssuerAuthorizationRepository>,
    ) -> Self {
        Self {
            authority,
            repository,
        }
    }
    pub fn authority(&self) -> &IssuerAuthority {
        &self.authority
    }
    pub async fn prepare(
        &self,
        current: &Secret,
        browser: &Secret,
        input: &IssuerAuthorizationInput<'_>,
    ) -> Result<IssuerAuthorizationStart> {
        let client = self
            .repository
            .load_issuer_client(self.authority.realm(), input.client)
            .await?;
        let request = IssuerAuthorizationRequest::new(self.authority.clone(), client, input)?;
        let handle = Secret::generate()?;
        let expires = self
            .repository
            .save_issuer_authorization(
                &request,
                current.verifier(),
                browser.verifier(),
                handle.verifier(),
            )
            .await?;
        Ok(IssuerAuthorizationStart::from_saved(
            &request, handle, expires,
        ))
    }
    pub async fn preview(
        &self,
        current: &Secret,
        browser: &Secret,
        handle: &Secret,
        authorization: Uuid,
    ) -> Result<IssuerAuthorizationPreview> {
        let data = self
            .repository
            .preview_issuer_authorization(&self.proof(current, browser, handle, authorization))
            .await?;
        if data.client.realm() != self.authority.realm() {
            return Err(crate::Error::Unavailable);
        }
        request::return_uri(&data.client, &data.redirect_uri)
            .map_err(|_| crate::Error::Unavailable)?;
        Ok(IssuerAuthorizationPreview {
            authorization,
            client: data.client.client(),
            redirect_uri: data.redirect_uri,
            expires_at_us: data.expires_at_us,
        })
    }
    pub async fn approve(
        &self,
        current: &Secret,
        browser: &Secret,
        handle: &Secret,
        authorization: Uuid,
    ) -> Result<IssuerAuthorizationReturn> {
        let code = Secret::generate()?;
        let data = self
            .repository
            .approve_issuer_authorization(
                &self.proof(current, browser, handle, authorization),
                code.verifier(),
            )
            .await?;
        response::destination(&self.authority, data, Some(&code))
    }
    pub async fn cancel(
        &self,
        current: &Secret,
        browser: &Secret,
        handle: &Secret,
        authorization: Uuid,
    ) -> Result<IssuerAuthorizationReturn> {
        let data = self
            .repository
            .cancel_issuer_authorization(&self.proof(current, browser, handle, authorization))
            .await?;
        response::destination(&self.authority, data, None)
    }
    pub async fn redeem(
        &self,
        authentication: &IssuerClientAuthentication,
        code: &Secret,
        redirect_uri: &str,
        pkce: &IssuerPkceVerifier,
        source: &str,
    ) -> IssuerTokenResult<IssuerRedeemedCode> {
        let client = self
            .client_for_token_operation(authentication, source)
            .await?;
        let facts = self
            .repository
            .redeem_issuer_code(&IssuerCodeRedemption {
                authority: &self.authority,
                client: &client,
                authentication,
                code: code.verifier(),
                redirect_uri,
                pkce: pkce.s256_digest(),
            })
            .await?;
        IssuerRedeemedCode::from_repository(self.authority.clone(), client, facts)
    }
    /// Shared issuer admission/registered-method selection, not a credential
    /// proof. Every consuming transaction still authenticates the current client.
    pub(in crate::issuer) async fn client_for_token_operation(
        &self,
        authentication: &IssuerClientAuthentication,
        source: &str,
    ) -> IssuerTokenResult<crate::IssuerClientRegistration> {
        if source.is_empty() || source.len() > 256 {
            return Err(IssuerTokenError::Unavailable);
        }
        let mut hash = Sha256::new();
        hash.update(b"easy-auth:issuer:token-source:");
        hash.update(source.as_bytes());
        self.repository
            .admit_issuer_redemption(&self.authority, hash.finalize().into())
            .await?;
        let client = self
            .repository
            .load_issuer_client(self.authority.realm(), authentication.client())
            .await
            .map_err(IssuerTokenError::client)?;
        if client.realm() != self.authority.realm() {
            return Err(IssuerTokenError::Unavailable);
        }
        authentication
            .validate_for(&client)
            .map_err(IssuerTokenError::client)?;
        Ok(client)
    }
    fn proof(
        &self,
        current: &Secret,
        browser: &Secret,
        handle: &Secret,
        authorization: Uuid,
    ) -> IssuerConsentProof<'_> {
        IssuerConsentProof {
            authorization,
            authority: &self.authority,
            current: current.verifier(),
            browser: browser.verifier(),
            handle: handle.verifier(),
        }
    }
}
