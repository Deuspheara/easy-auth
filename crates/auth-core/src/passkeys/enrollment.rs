use super::{
    PasskeyCreationOptions, PasskeyEnrollmentRequest, PasskeyEnrollmentStart,
    PasskeyRegistrationResponse, PasskeyRepository, PasskeyService, configuration,
};
use crate::{Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

pub struct PasskeyEnrollmentOptions {
    pub transaction: Uuid,
    pub options: PasskeyCreationOptions,
}

/// Enrollment use cases shared by embedded and standalone composition. Normal server
/// composition remains disabled until passkey sign-in and assurance policy are available.
pub struct PasskeyEnrollment {
    realm: Uuid,
    service: Arc<PasskeyService>,
    repository: Arc<dyn PasskeyRepository>,
}

impl PasskeyEnrollment {
    pub fn realm(&self) -> Uuid {
        self.realm
    }
    pub fn origin(&self) -> &str {
        self.service.origin()
    }
    pub fn new(
        realm: Uuid,
        service: Arc<PasskeyService>,
        repository: Arc<dyn PasskeyRepository>,
    ) -> Self {
        Self {
            realm,
            service,
            repository,
        }
    }

    pub async fn begin(
        &self,
        session: &Secret,
        browser: &Secret,
        source: &str,
        label: &str,
    ) -> Result<PasskeyEnrollmentOptions> {
        self.begin_with_residence(session, browser, source, label, false)
            .await
    }

    pub async fn begin_discoverable(
        &self,
        session: &Secret,
        browser: &Secret,
        source: &str,
        label: &str,
    ) -> Result<PasskeyEnrollmentOptions> {
        self.begin_with_residence(session, browser, source, label, true)
            .await
    }

    async fn begin_with_residence(
        &self,
        session: &Secret,
        browser: &Secret,
        source: &str,
        label: &str,
        discoverable: bool,
    ) -> Result<PasskeyEnrollmentOptions> {
        configuration::display_name(label)?;
        let context = self
            .repository
            .enrollment_context(self.realm, session.verifier(), self.service.rp_id())
            .await?;
        let (options, state) = if discoverable {
            self.service.begin_discoverable_registration(
                context.user_id,
                &context.account_name,
                &context.excluded_credentials,
            )?
        } else {
            self.service.begin_registration(
                context.user_id,
                &context.account_name,
                &context.excluded_credentials,
            )?
        };
        let transaction = Uuid::new_v4();
        self.repository
            .save_enrollment(PasskeyEnrollmentStart {
                request: self.request(session, browser, source, transaction),
                user_id: context.user_id,
                rp_id: self.service.rp_id().to_owned(),
                label: label.to_owned(),
                state,
            })
            .await?;
        Ok(PasskeyEnrollmentOptions {
            transaction,
            options,
        })
    }

    pub async fn finish(
        &self,
        session: &Secret,
        browser: &Secret,
        source: &str,
        transaction: Uuid,
        response: &PasskeyRegistrationResponse,
    ) -> Result<Uuid> {
        let request = self.request(session, browser, source, transaction);
        let state = self.repository.load_enrollment(&request).await?;
        let expected_state = state.encode_for_database()?;
        let credential = self.service.verify_registration(response, state)?;
        self.repository
            .commit_enrollment(&request, &expected_state, credential)
            .await
    }

    fn request(
        &self,
        session: &Secret,
        browser: &Secret,
        source: &str,
        transaction: Uuid,
    ) -> PasskeyEnrollmentRequest {
        PasskeyEnrollmentRequest {
            realm: self.realm,
            session: session.verifier(),
            browser: browser.verifier(),
            source: Sha256::digest(source.as_bytes()).into(),
            transaction,
        }
    }
}
