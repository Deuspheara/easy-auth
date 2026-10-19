mod admission;
mod completion;
mod preparation;

use crate::Postgres;
use async_trait::async_trait;
use auth_core::{
    PasskeySignupRegistrationContext, PasskeySignupRepository, PasskeySignupRequest,
    PasskeySignupStart, PrivatePasskeyAuthentication, Result, StoredPasskey,
    VerifiedPasskeyAuthentication, VerifiedPasskeySignupRegistration, Verifier,
};

#[async_trait]
impl PasskeySignupRepository for Postgres {
    async fn save_signup(&self, pending: PasskeySignupStart) -> Result<()> {
        preparation::save(&self.pool, pending).await
    }
    async fn load_signup_registration(
        &self,
        request: &PasskeySignupRequest,
        rp_id: &str,
    ) -> Result<PasskeySignupRegistrationContext> {
        preparation::load(&self.pool, request, rp_id).await
    }
    async fn advance_signup(
        &self,
        request: &PasskeySignupRequest,
        registration: VerifiedPasskeySignupRegistration,
    ) -> Result<()> {
        preparation::advance(&self.pool, request, registration).await
    }
    async fn load_signup_authentication(
        &self,
        request: &PasskeySignupRequest,
        rp_id: &str,
    ) -> Result<(PrivatePasskeyAuthentication, StoredPasskey)> {
        completion::load(&self.pool, request, rp_id).await
    }
    async fn commit_signup(
        &self,
        request: &PasskeySignupRequest,
        proof: VerifiedPasskeyAuthentication,
        session: Verifier,
    ) -> Result<()> {
        completion::commit(&self.pool, request, proof, session).await
    }
}
