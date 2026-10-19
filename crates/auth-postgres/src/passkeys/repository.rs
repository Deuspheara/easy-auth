use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    PasskeyEnrollmentContext, PasskeyEnrollmentRequest, PasskeyEnrollmentStart, PasskeyRepository,
    PrivatePasskeyRegistration, Result, VerifiedPasskey, Verifier,
};
use uuid::Uuid;

#[async_trait]
impl PasskeyRepository for Postgres {
    async fn enrollment_context(
        &self,
        realm: Uuid,
        session: Verifier,
        rp_id: &str,
    ) -> Result<PasskeyEnrollmentContext> {
        super::preparation::context(&self.pool, realm, session, rp_id).await
    }
    async fn save_enrollment(&self, pending: PasskeyEnrollmentStart) -> Result<()> {
        super::preparation::save(&self.pool, pending).await
    }
    async fn load_enrollment(
        &self,
        request: &PasskeyEnrollmentRequest,
    ) -> Result<PrivatePasskeyRegistration> {
        super::completion::load(&self.pool, request).await
    }
    async fn commit_enrollment(
        &self,
        request: &PasskeyEnrollmentRequest,
        expected_state: &[u8],
        credential: VerifiedPasskey,
    ) -> Result<Uuid> {
        super::completion::commit(&self.pool, request, expected_state, credential).await
    }
}
