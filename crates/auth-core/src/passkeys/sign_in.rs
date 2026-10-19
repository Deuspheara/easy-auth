use super::{
    PasskeyAuthenticationOptions, PasskeyAuthenticationRepository, PasskeyAuthenticationRequest,
    PasskeyAuthenticationResponse, PasskeyAuthenticationStart, PasskeyService,
};
use crate::{Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

pub struct PasskeySignInOptions {
    pub transaction: Uuid,
    pub options: PasskeyAuthenticationOptions,
}

enum SignInMode {
    Account(Uuid),
    Conditional,
    Modal,
}

/// Explicit optional composition. No normal HTTP/server login route enables this
/// until account selection and stronger-account policy have been reviewed.
pub struct PasskeySignIn {
    realm: Uuid,
    service: Arc<PasskeyService>,
    repository: Arc<dyn PasskeyAuthenticationRepository>,
}

impl PasskeySignIn {
    pub fn new(
        realm: Uuid,
        service: Arc<PasskeyService>,
        repository: Arc<dyn PasskeyAuthenticationRepository>,
    ) -> Self {
        Self {
            realm,
            service,
            repository,
        }
    }

    pub fn realm(&self) -> Uuid {
        self.realm
    }
    pub fn origin(&self) -> &str {
        self.service.origin()
    }

    /// The caller must identify this opaque account without exposing email-based
    /// credential enumeration. The account ID alone never establishes authentication.
    pub async fn begin_account(
        &self,
        owner: Uuid,
        browser: &Secret,
        source: &str,
    ) -> Result<PasskeySignInOptions> {
        self.begin(SignInMode::Account(owner), browser, source)
            .await
    }

    pub async fn begin_discoverable(
        &self,
        browser: &Secret,
        source: &str,
    ) -> Result<PasskeySignInOptions> {
        self.begin(SignInMode::Conditional, browser, source).await
    }

    pub async fn begin_modal(
        &self,
        browser: &Secret,
        source: &str,
    ) -> Result<PasskeySignInOptions> {
        self.begin(SignInMode::Modal, browser, source).await
    }

    async fn begin(
        &self,
        mode: SignInMode,
        browser: &Secret,
        source: &str,
    ) -> Result<PasskeySignInOptions> {
        let request = self.request(browser, source, Uuid::new_v4());
        let owner = match mode {
            SignInMode::Account(owner) => Some(owner),
            _ => None,
        };
        let credentials = self
            .repository
            .prepare_authentication(&request, self.service.rp_id(), owner)
            .await?;
        let (options, state) = match mode {
            SignInMode::Account(owner) => {
                self.service
                    .begin_account_authentication(self.realm, owner, &credentials)?
            }
            SignInMode::Conditional => {
                self.service.begin_discoverable_authentication(self.realm)?
            }
            SignInMode::Modal => self.service.begin_modal_authentication(self.realm)?,
        };
        let transaction = request.transaction;
        self.repository
            .save_authentication(PasskeyAuthenticationStart {
                request,
                rp_id: self.service.rp_id().to_owned(),
                state,
            })
            .await?;
        Ok(PasskeySignInOptions {
            transaction,
            options,
        })
    }

    pub async fn finish(
        &self,
        browser: &Secret,
        source: &str,
        transaction: Uuid,
        response: &PasskeyAuthenticationResponse,
    ) -> Result<Secret> {
        let request = self.request(browser, source, transaction);
        // Admission precedes protocol checks; malformed attempts also spend budget.
        let (state, credential) = self
            .repository
            .load_authentication(&request, self.service.rp_id(), response.raw_id.as_slice())
            .await?;
        let proof = self
            .service
            .verify_authentication(response, state, credential)?;
        let session = Secret::generate()?;
        self.repository
            .commit_authentication(&request, proof, session.verifier())
            .await?;
        Ok(session)
    }

    fn request(
        &self,
        browser: &Secret,
        source: &str,
        transaction: Uuid,
    ) -> PasskeyAuthenticationRequest {
        PasskeyAuthenticationRequest {
            realm: self.realm,
            transaction,
            browser: browser.verifier(),
            source: Sha256::digest(source.as_bytes()).into(),
        }
    }
}
