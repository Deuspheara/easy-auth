use super::{
    OAuthBrowserProof, OAuthCallback, OAuthConnection, OAuthIntent, OAuthPurpose, OAuthRequest,
    OAuthTransactionRepository,
};
use crate::{Error, Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::Arc;

#[derive(Debug)]
pub struct OAuthStart {
    pub state: Secret,
    pub proof: OAuthBrowserProof,
    pub expires_us: i64,
}

/// Permission to attempt a provider exchange, NOT verified provider identity or
/// a session grant. Future commit must recheck deadline, configuration and owner.
pub struct OAuthExchange {
    configuration: OAuthConnection,
    purpose: OAuthPurpose,
    expires_us: i64,
    proof: OAuthBrowserProof,
    redirect: String,
}

impl OAuthExchange {
    /// Exact admitted operation return; wire exchange must not substitute the anchor.
    pub fn redirect(&self) -> &str {
        &self.redirect
    }
    pub fn configuration(&self) -> &OAuthConnection {
        &self.configuration
    }
    pub fn purpose(&self) -> &OAuthPurpose {
        &self.purpose
    }
    pub fn expires_us(&self) -> i64 {
        self.expires_us
    }
    pub fn proof(&self) -> &OAuthBrowserProof {
        &self.proof
    }
}

pub struct OAuthTransactions {
    configuration: OAuthConnection,
    repository: Arc<dyn OAuthTransactionRepository>,
    redirect: String,
}

impl OAuthTransactions {
    /// Trusted immutable configuration used to align composed protocol services.
    pub fn configuration(&self) -> &OAuthConnection {
        &self.configuration
    }

    pub fn new(
        configuration: OAuthConnection,
        repository: Arc<dyn OAuthTransactionRepository>,
    ) -> Self {
        Self {
            redirect: configuration.redirect().to_owned(),
            configuration,
            repository,
        }
    }
    /// Trusted native construction only, after binding the actual listener.
    pub fn for_desktop_return(
        configuration: OAuthConnection,
        repository: Arc<dyn OAuthTransactionRepository>,
        redirect: super::OAuthRedirect,
    ) -> Result<Self> {
        if configuration.redirect_policy() != super::OAuthRedirectPolicy::DesktopLoopback
            || !configuration.permits_return(redirect.as_str())
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            configuration,
            repository,
            redirect: redirect.as_str().to_owned(),
        })
    }
    pub fn redirect(&self) -> &str {
        &self.redirect
    }
    pub async fn begin(&self, intent: &OAuthIntent<'_>) -> Result<OAuthStart> {
        let state = Secret::generate()?;
        let proof = OAuthBrowserProof::generate()?;
        let request = self.request(intent, &state, &proof)?;
        let expires_us = self
            .repository
            .save_oauth_return(&request, &self.redirect)
            .await?;
        Ok(OAuthStart {
            state,
            proof,
            expires_us,
        })
    }
    pub async fn consume(
        &self,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: OAuthBrowserProof,
        callback: OAuthCallback<'_>,
    ) -> Result<OAuthExchange> {
        if self.redirect == self.configuration.redirect() {
            self.configuration.validate_callback(&callback)?;
        } else {
            self.configuration
                .validate_callback_at(&callback, &self.redirect)?;
        }
        let request = self.request(intent, state, &proof)?;
        let expires_us = self
            .repository
            .consume_oauth_return(&request, &self.redirect)
            .await?;
        Ok(OAuthExchange {
            configuration: self.configuration.clone(),
            purpose: intent.purpose.clone(),
            expires_us,
            proof,
            redirect: self.redirect.clone(),
        })
    }
    pub async fn cancel(
        &self,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: &OAuthBrowserProof,
    ) -> Result<()> {
        let request = self.request(intent, state, proof)?;
        self.repository
            .cancel_oauth_return(&request, &self.redirect)
            .await
    }
    fn request(
        &self,
        intent: &OAuthIntent<'_>,
        state: &Secret,
        proof: &OAuthBrowserProof,
    ) -> Result<OAuthRequest> {
        if (self.configuration.redirect_policy() == super::OAuthRedirectPolicy::DesktopLoopback
            && !matches!(intent.purpose, OAuthPurpose::SignIn))
            || intent.source.is_empty()
            || intent.source.len() > 256
            || intent.source.chars().any(char::is_control)
            || matches!(intent.purpose,
                OAuthPurpose::Link { user, .. } | OAuthPurpose::DeleteProviderAccount { user, .. }
                if user.is_nil())
        {
            return Err(Error::InvalidInput);
        }
        Ok(OAuthRequest {
            configuration: self.configuration.clone(),
            purpose: intent.purpose.clone(),
            browser: intent.browser.verifier(),
            source: Sha256::digest(intent.source.as_bytes()).into(),
            state: state.verifier(),
            nonce: proof.nonce().verifier(),
            pkce: proof.pkce_verifier().verifier(),
        })
    }
}
