use super::{PasskeyRecoverySetupRepository, PasskeyRecoverySetupRequest};
use crate::{PasskeyService, Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// Experimental configuration only; no recovery login or activation is provided.
pub struct PasskeyRecoverySetup {
    realm: Uuid,
    service: Arc<PasskeyService>,
    repository: Arc<dyn PasskeyRecoverySetupRepository>,
}

/// Expose the code once at a protected transport boundary. Neither Serialize nor
/// Debug: applications must not log it or put it in URLs, email or browser storage.
pub struct PreparedPasskeyRecoveryCode {
    pub id: Uuid,
    pub code: Secret,
}

impl PasskeyRecoverySetup {
    pub fn new(
        realm: Uuid,
        service: Arc<PasskeyService>,
        repository: Arc<dyn PasskeyRecoverySetupRepository>,
    ) -> Self {
        Self {
            realm,
            service,
            repository,
        }
    }

    pub async fn prepare(
        &self,
        session: &Secret,
        source: &str,
    ) -> Result<PreparedPasskeyRecoveryCode> {
        let code = Secret::generate()?;
        let id = Uuid::new_v4();
        self.repository
            .prepare_passkey_recovery_code(&self.request(session, source), id, code.verifier())
            .await?;
        Ok(PreparedPasskeyRecoveryCode { id, code })
    }

    pub async fn confirm(
        &self,
        session: &Secret,
        source: &str,
        id: Uuid,
        code: &Secret,
    ) -> Result<()> {
        self.repository
            .confirm_passkey_recovery_code(&self.request(session, source), id, code.verifier())
            .await
    }

    fn request(&self, session: &Secret, source: &str) -> PasskeyRecoverySetupRequest {
        PasskeyRecoverySetupRequest {
            realm: self.realm,
            session: session.verifier(),
            rp_id: self.service.rp_id().to_owned(),
            source: Sha256::digest(source.as_bytes()).into(),
        }
    }
}
