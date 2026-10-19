use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    PasskeyAuthenticationRepository, PasskeyAuthenticationRequest, PasskeyAuthenticationStart,
    PrivatePasskeyAuthentication, Result, StoredPasskey, VerifiedPasskeyAuthentication, Verifier,
};
use uuid::Uuid;

#[async_trait]
impl PasskeyAuthenticationRepository for Postgres {
    async fn prepare_authentication(
        &self,
        request: &PasskeyAuthenticationRequest,
        rp_id: &str,
        owner: Option<Uuid>,
    ) -> Result<Vec<StoredPasskey>> {
        super::preparation::prepare(&self.pool, request, rp_id, owner).await
    }
    async fn save_authentication(&self, pending: PasskeyAuthenticationStart) -> Result<()> {
        super::preparation::save(&self.pool, pending).await
    }
    async fn load_authentication(
        &self,
        request: &PasskeyAuthenticationRequest,
        rp_id: &str,
        credential_id: &[u8],
    ) -> Result<(PrivatePasskeyAuthentication, StoredPasskey)> {
        super::completion::load(&self.pool, request, rp_id, credential_id).await
    }
    async fn commit_authentication(
        &self,
        request: &PasskeyAuthenticationRequest,
        proof: VerifiedPasskeyAuthentication,
        session: Verifier,
    ) -> Result<()> {
        super::completion::commit(&self.pool, request, proof, session).await
    }
}
