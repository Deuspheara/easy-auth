use super::super::{
    PasskeyAuthenticationOptions, PasskeyAuthenticationResponse, PasskeyCreationOptions,
    PasskeyRegistrationResponse, PasskeyService, StoredPasskey, configuration,
};
use super::{
    PasskeySignupRepository, PasskeySignupRequest, PasskeySignupStart,
    VerifiedPasskeySignupRegistration,
};
use crate::{Error, Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

pub struct PasskeySignupCreation {
    pub transaction: Uuid,
    pub options: PasskeyCreationOptions,
}

pub struct PasskeySignupAssertion {
    pub transaction: Uuid,
    pub options: PasskeyAuthenticationOptions,
}

/// Explicit experimental signup; registration alone cannot establish a session.
pub struct PasskeySignup {
    realm: Uuid,
    service: Arc<PasskeyService>,
    repository: Arc<dyn PasskeySignupRepository>,
}

impl PasskeySignup {
    pub fn new(
        realm: Uuid,
        service: Arc<PasskeyService>,
        repository: Arc<dyn PasskeySignupRepository>,
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

    pub async fn begin(
        &self,
        display_name: &str,
        browser: &Secret,
        source: &str,
    ) -> Result<PasskeySignupCreation> {
        configuration::display_name(display_name)?;
        if self.realm.is_nil() {
            return Err(Error::InvalidInput);
        }
        let request = self.request(browser, source, Uuid::new_v4());
        let transaction = request.transaction;
        let owner = Uuid::new_v4();
        let (options, state) =
            self.service
                .begin_discoverable_registration(owner, display_name, &[])?;
        self.repository
            .save_signup(PasskeySignupStart {
                request,
                prospective_user: owner,
                rp_id: self.service.rp_id().to_owned(),
                display_name: display_name.to_owned(),
                state,
            })
            .await?;
        Ok(PasskeySignupCreation {
            transaction,
            options,
        })
    }

    pub async fn finish_registration(
        &self,
        browser: &Secret,
        source: &str,
        transaction: Uuid,
        response: &PasskeyRegistrationResponse,
    ) -> Result<PasskeySignupAssertion> {
        let request = self.request(browser, source, transaction);
        let context = self
            .repository
            .load_signup_registration(&request, self.service.rp_id())
            .await?;
        let expected_state = context.state.encode_for_database()?;
        let candidate = self.service.verify_registration(response, context.state)?;
        let stored = StoredPasskey::decode_from_database(
            self.realm,
            context.prospective_user,
            candidate.rp_id(),
            candidate.credential_id(),
            &candidate.encode_for_database()?,
        )?;
        let (options, assertion) = self.service.begin_account_authentication(
            self.realm,
            context.prospective_user,
            &[stored],
        )?;
        self.repository
            .advance_signup(
                &request,
                VerifiedPasskeySignupRegistration {
                    owner: context.prospective_user,
                    expected_state,
                    candidate,
                    assertion,
                },
            )
            .await?;
        Ok(PasskeySignupAssertion {
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
        let (state, candidate) = self
            .repository
            .load_signup_authentication(&request, self.service.rp_id())
            .await?;
        let proof = self
            .service
            .verify_authentication(response, state, candidate)?;
        let session = Secret::generate()?;
        self.repository
            .commit_signup(&request, proof, session.verifier())
            .await?;
        Ok(session)
    }

    fn request(&self, browser: &Secret, source: &str, transaction: Uuid) -> PasskeySignupRequest {
        PasskeySignupRequest {
            realm: self.realm,
            transaction,
            browser: browser.verifier(),
            source: Sha256::digest(source.as_bytes()).into(),
        }
    }
}
