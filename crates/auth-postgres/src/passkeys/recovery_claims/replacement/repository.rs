use super::super::admission;
use super::{completion, preparation};
use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    PasskeyRecoveryReplacementRepository, PasskeyRecoveryReplacementRequest,
    PasskeyRecoveryReplacementStart, PrivatePasskeyAuthentication, PrivatePasskeyRegistration,
    Result, StoredPasskey, VerifiedPasskeyAuthentication, VerifiedPasskeyRecoveryRegistration,
    Verifier,
};
#[async_trait]
impl PasskeyRecoveryReplacementRepository for Postgres {
    async fn save_recovery_replacement(
        &self,
        pending: PasskeyRecoveryReplacementStart,
    ) -> Result<()> {
        admission::admit(self, &pending.request.claim, admission::Budget::Browser).await?;
        preparation::save(&self.pool, pending).await
    }
    async fn load_recovery_registration(
        &self,
        r: &PasskeyRecoveryReplacementRequest,
    ) -> Result<PrivatePasskeyRegistration> {
        admission::admit(self, &r.claim, admission::Budget::Browser).await?;
        preparation::load(&self.pool, r).await
    }
    async fn advance_recovery_replacement(
        &self,
        r: &PasskeyRecoveryReplacementRequest,
        registration: VerifiedPasskeyRecoveryRegistration,
    ) -> Result<()> {
        preparation::advance(&self.pool, r, registration).await
    }
    async fn load_recovery_assertion(
        &self,
        r: &PasskeyRecoveryReplacementRequest,
    ) -> Result<(PrivatePasskeyAuthentication, StoredPasskey)> {
        admission::admit(self, &r.claim, admission::Budget::Browser).await?;
        completion::load(&self.pool, r).await
    }
    async fn commit_recovery_replacement(
        &self,
        r: &PasskeyRecoveryReplacementRequest,
        proof: VerifiedPasskeyAuthentication,
        session: Verifier,
    ) -> Result<()> {
        completion::commit(&self.pool, r, proof, session).await
    }
}
