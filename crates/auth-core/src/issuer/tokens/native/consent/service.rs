use super::{
    IssuerNativeAuthorizationDestination, IssuerNativeAuthorizationInput,
    IssuerNativeAuthorizationPreview, IssuerNativeAuthorizationRepository,
    IssuerNativeAuthorizationRequest, IssuerNativeAuthorizationStart,
};
use crate::issuer::codes::{authorization_destination, validate_return_uri};
use crate::{
    Error, IssuerAuthority, IssuerAuthorizationReturn, IssuerAuthorizationStart,
    IssuerConsentProof, Result, Secret,
};
use std::sync::Arc;
use uuid::Uuid;

pub struct IssuerNativeAuthorization {
    authority: IssuerAuthority,
    repository: Arc<dyn IssuerNativeAuthorizationRepository>,
}
impl IssuerNativeAuthorization {
    pub fn new(
        authority: IssuerAuthority,
        repository: Arc<dyn IssuerNativeAuthorizationRepository>,
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
        input: &IssuerNativeAuthorizationInput<'_>,
    ) -> Result<IssuerNativeAuthorizationStart> {
        let policy = self
            .repository
            .load_issuer_native_refresh_policy(&self.authority, input.authorization.client)
            .await?;
        if policy.authority() != &self.authority {
            return Err(Error::Unavailable);
        }
        let request = IssuerNativeAuthorizationRequest::new(policy, input)?;
        let handle = Secret::generate()?;
        let saved = self
            .repository
            .save_issuer_native_authorization(
                &request,
                current.verifier(),
                browser.verifier(),
                handle.verifier(),
            )
            .await?;
        if &saved.consent.policy != request.policy() {
            return Err(Error::Unavailable);
        }
        saved.consent.validate(
            &self.authority,
            request.code().client(),
            saved.expires_at_us,
            false,
        )?;
        Ok(IssuerNativeAuthorizationStart {
            code: IssuerAuthorizationStart::from_saved(request.code(), handle, saved.expires_at_us),
            grant_expires_at_us: saved.consent.grant_expires_at_us,
            idle_seconds: saved.consent.policy.idle_seconds(),
        })
    }
    pub async fn preview(
        &self,
        current: &Secret,
        browser: &Secret,
        handle: &Secret,
        authorization: Uuid,
    ) -> Result<IssuerNativeAuthorizationPreview> {
        let data = self
            .repository
            .preview_issuer_native_authorization(&self.proof(
                current,
                browser,
                handle,
                authorization,
            ))
            .await?;
        self.validate(&data, false)?;
        Ok(IssuerNativeAuthorizationPreview {
            authorization,
            client: data.destination.client.client(),
            redirect_uri: data.destination.redirect_uri,
            expires_at_us: data.destination.expires_at_us,
            grant_expires_at_us: data.consent.grant_expires_at_us,
            idle_seconds: data.consent.policy.idle_seconds(),
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
            .approve_issuer_native_authorization(
                &self.proof(current, browser, handle, authorization),
                code.verifier(),
            )
            .await?;
        self.validate(&data, true)?;
        authorization_destination(&self.authority, data.destination, Some(&code))
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
            .cancel_issuer_native_authorization(&self.proof(
                current,
                browser,
                handle,
                authorization,
            ))
            .await?;
        if data.client.supports_online_authorization() {
            return Err(Error::Unavailable);
        }
        authorization_destination(&self.authority, data, None)
    }
    fn validate(&self, data: &IssuerNativeAuthorizationDestination, approved: bool) -> Result<()> {
        data.consent.validate(
            &self.authority,
            &data.destination.client,
            data.destination.expires_at_us,
            approved,
        )?;
        validate_return_uri(&data.destination.client, &data.destination.redirect_uri)
            .map_err(|_| Error::Unavailable)
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
