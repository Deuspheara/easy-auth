use super::{PasskeyInfo, PasskeyManagementRepository, PasskeyManagementRequest};
use crate::passkeys::{PasskeyService, configuration};
use crate::{Result, Secret};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

/// Explicit experimental management. This does not activate stronger-account recovery.
pub struct PasskeyManagement {
    realm: Uuid,
    service: Arc<PasskeyService>,
    repository: Arc<dyn PasskeyManagementRepository>,
}

impl PasskeyManagement {
    pub fn new(
        realm: Uuid,
        service: Arc<PasskeyService>,
        repository: Arc<dyn PasskeyManagementRepository>,
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

    pub async fn list(&self, session: &Secret, source: &str) -> Result<Vec<PasskeyInfo>> {
        self.repository
            .list_passkeys(&self.request(session, source))
            .await
    }

    pub async fn rename(
        &self,
        session: &Secret,
        source: &str,
        id: Uuid,
        version: Uuid,
        label: &str,
    ) -> Result<Uuid> {
        configuration::display_name(label)?;
        self.repository
            .rename_passkey(&self.request(session, source), id, version, label)
            .await
    }

    /// Revokes every current session; a proven remaining key must sign in again.
    pub async fn remove(
        &self,
        session: &Secret,
        source: &str,
        id: Uuid,
        version: Uuid,
    ) -> Result<()> {
        self.repository
            .remove_passkey(&self.request(session, source), id, version)
            .await
    }

    fn request(&self, session: &Secret, source: &str) -> PasskeyManagementRequest {
        PasskeyManagementRequest {
            realm: self.realm,
            session: session.verifier(),
            rp_id: self.service.rp_id().to_owned(),
            source: Sha256::digest(source.as_bytes()).into(),
        }
    }
}
