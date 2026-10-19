use super::{
    PasskeyRecoveryReplacementRepository, PasskeyRecoveryReplacementRequest,
    PasskeyRecoveryReplacementStart, VerifiedPasskeyRecoveryRegistration,
};
use crate::{
    PasskeyAuthenticationOptions, PasskeyAuthenticationResponse, PasskeyCreationOptions,
    PasskeyRecoveryClaimRequest, PasskeyRegistrationResponse, PasskeyService, Result, Secret,
    StoredPasskey,
};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use uuid::Uuid;

#[derive(Clone, Copy, Debug)]
pub struct PasskeyRecoveryTarget {
    pub user_id: Uuid,
    pub claim_id: Uuid,
}

pub struct PasskeyRecoveryCreation {
    pub transaction: Uuid,
    pub options: PasskeyCreationOptions,
}
pub struct PasskeyRecoveryAssertion {
    pub transaction: Uuid,
    pub options: PasskeyAuthenticationOptions,
}

/// Explicit experimental recovery. Saved proof and delay alone cannot issue a session.
pub struct PasskeyRecoveryReplacement {
    realm: Uuid,
    service: Arc<PasskeyService>,
    repository: Arc<dyn PasskeyRecoveryReplacementRepository>,
}
impl PasskeyRecoveryReplacement {
    pub fn new(
        realm: Uuid,
        service: Arc<PasskeyService>,
        repository: Arc<dyn PasskeyRecoveryReplacementRepository>,
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
        target: PasskeyRecoveryTarget,
        browser: &Secret,
        source: &str,
    ) -> Result<PasskeyRecoveryCreation> {
        let transaction = Uuid::new_v4();
        // Recovery replaces existing keys; it does not disclose their allow-list.
        let (options, state) = self.service.begin_discoverable_registration(
            target.user_id,
            &target.user_id.to_string(),
            &[],
        )?;
        self.repository
            .save_recovery_replacement(PasskeyRecoveryReplacementStart {
                request: self.request(target, transaction, browser, source),
                state,
            })
            .await?;
        Ok(PasskeyRecoveryCreation {
            transaction,
            options,
        })
    }
    pub async fn finish_registration(
        &self,
        target: PasskeyRecoveryTarget,
        transaction: Uuid,
        browser: &Secret,
        source: &str,
        response: &PasskeyRegistrationResponse,
    ) -> Result<PasskeyRecoveryAssertion> {
        let request = self.request(target, transaction, browser, source);
        let state = self.repository.load_recovery_registration(&request).await?;
        let expected = state.encode_for_database()?;
        let candidate = self.service.verify_registration(response, state)?;
        let stored = StoredPasskey::decode_from_database(
            self.realm,
            target.user_id,
            candidate.rp_id(),
            candidate.credential_id(),
            &candidate.encode_for_database()?,
        )?;
        let (options, assertion) =
            self.service
                .begin_account_authentication(self.realm, target.user_id, &[stored])?;
        self.repository
            .advance_recovery_replacement(
                &request,
                VerifiedPasskeyRecoveryRegistration {
                    owner: target.user_id,
                    expected,
                    candidate,
                    assertion,
                },
            )
            .await?;
        Ok(PasskeyRecoveryAssertion {
            transaction,
            options,
        })
    }
    pub async fn finish(
        &self,
        target: PasskeyRecoveryTarget,
        transaction: Uuid,
        browser: &Secret,
        source: &str,
        response: &PasskeyAuthenticationResponse,
    ) -> Result<Secret> {
        let request = self.request(target, transaction, browser, source);
        let (state, candidate) = self.repository.load_recovery_assertion(&request).await?;
        let proof = self
            .service
            .verify_authentication(response, state, candidate)?;
        let session = Secret::generate()?;
        self.repository
            .commit_recovery_replacement(&request, proof, session.verifier())
            .await?;
        Ok(session)
    }
    fn request(
        &self,
        target: PasskeyRecoveryTarget,
        transaction: Uuid,
        browser: &Secret,
        source: &str,
    ) -> PasskeyRecoveryReplacementRequest {
        PasskeyRecoveryReplacementRequest {
            claim: PasskeyRecoveryClaimRequest {
                realm: self.realm,
                user_id: target.user_id,
                rp_id: self.service.rp_id().into(),
                browser: browser.verifier(),
                source: Sha256::digest(source.as_bytes()).into(),
            },
            claim_id: target.claim_id,
            transaction,
        }
    }
}
