use super::{
    PasskeyRecoveryClaimInfo, PasskeyRecoveryClaimRepository, PasskeyRecoveryClaimRequest,
    PasskeyRecoveryKeyCancellation,
};
use crate::{PasskeyService, Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// Experimental scheduling/cancellation only. This issues no session or key.
pub struct PasskeyRecoveryClaims {
    realm: Uuid,
    service: Arc<PasskeyService>,
    repository: Arc<dyn PasskeyRecoveryClaimRepository>,
}

impl PasskeyRecoveryClaims {
    /// An alerted owner who lost every key can still deny a fraudulent claim
    /// using the retained saved code. This never revives the consumed code.
    pub async fn cancel_with_code(&self, user_id: Uuid, code: &Secret, source: &str) -> Result<()> {
        self.repository
            .cancel_passkey_recovery_with_code(&super::PasskeyRecoveryCodeCancellation {
                realm: self.realm,
                user_id,
                rp_id: self.service.rp_id().into(),
                code: code.verifier(),
                source: Sha256::digest(source.as_bytes()).into(),
            })
            .await
    }
    pub fn new(
        realm: Uuid,
        service: Arc<PasskeyService>,
        repository: Arc<dyn PasskeyRecoveryClaimRepository>,
    ) -> Self {
        Self {
            realm,
            service,
            repository,
        }
    }

    pub async fn begin(
        &self,
        user_id: Uuid,
        code: &Secret,
        browser: &Secret,
        source: &str,
    ) -> Result<PasskeyRecoveryClaimInfo> {
        self.repository
            .begin_passkey_recovery_claim(
                &self.request(user_id, browser, source),
                Uuid::new_v4(),
                code.verifier(),
            )
            .await
    }

    pub async fn resume(
        &self,
        user_id: Uuid,
        browser: &Secret,
        source: &str,
    ) -> Result<PasskeyRecoveryClaimInfo> {
        self.repository
            .resume_passkey_recovery_claim(&self.request(user_id, browser, source))
            .await
    }

    pub async fn status(
        &self,
        user_id: Uuid,
        browser: &Secret,
        source: &str,
        id: Uuid,
    ) -> Result<PasskeyRecoveryClaimInfo> {
        self.repository
            .passkey_recovery_claim(&self.request(user_id, browser, source), id)
            .await
    }

    pub async fn cancel(
        &self,
        user_id: Uuid,
        browser: &Secret,
        source: &str,
        id: Uuid,
    ) -> Result<()> {
        self.repository
            .cancel_passkey_recovery_claim(&self.request(user_id, browser, source), id)
            .await
    }

    pub async fn cancel_with_key(&self, session: &Secret, source: &str, id: Uuid) -> Result<()> {
        let request = PasskeyRecoveryKeyCancellation {
            realm: self.realm,
            rp_id: self.service.rp_id().into(),
            session: session.verifier(),
            source: Sha256::digest(source.as_bytes()).into(),
        };
        self.repository
            .cancel_passkey_recovery_with_key(&request, id)
            .await
    }

    fn request(
        &self,
        user_id: Uuid,
        browser: &Secret,
        source: &str,
    ) -> PasskeyRecoveryClaimRequest {
        PasskeyRecoveryClaimRequest {
            realm: self.realm,
            user_id,
            rp_id: self.service.rp_id().into(),
            browser: browser.verifier(),
            source: Sha256::digest(source.as_bytes()).into(),
        }
    }
}
