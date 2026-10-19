mod binding;
mod concurrency;
mod migration;
mod waiting;

use super::{Fixture, ORIGIN, SOURCE};
use auth_core::{
    PasskeyAuthenticationRepository, PasskeyAuthenticationRequest, PasskeyAuthenticationResponse,
    PasskeySignIn, Repository, Secret, VerifiedPasskeyAuthentication,
};
use sqlx::PgPool;
use uuid::Uuid;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

struct SignIn {
    enrollment: Fixture,
    flow: PasskeySignIn,
    token: SoftToken,
    owner: Uuid,
    credential_id: String,
}

impl SignIn {
    async fn new(pool: PgPool) -> Self {
        let enrollment = Fixture::new(pool).await;
        let owner = enrollment
            .store
            .authenticate(enrollment.realm, enrollment.session.verifier())
            .await
            .unwrap()
            .id;
        let pending = enrollment
            .enrollment
            .begin(
                &enrollment.session,
                &enrollment.browser,
                SOURCE,
                "Security key",
            )
            .await
            .unwrap();
        let (mut token, _) = SoftToken::new(true).unwrap();
        let response = token
            .perform_register(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        enrollment
            .enrollment
            .finish(
                &enrollment.session,
                &enrollment.browser,
                SOURCE,
                pending.transaction,
                &response,
            )
            .await
            .unwrap();
        let flow = PasskeySignIn::new(
            enrollment.realm,
            enrollment.service.clone(),
            enrollment.store.clone(),
        );
        Self {
            enrollment,
            flow,
            token,
            owner,
            credential_id: response.id,
        }
    }

    async fn begin(&mut self) -> (Uuid, PasskeyAuthenticationResponse) {
        let pending = self
            .flow
            .begin_account(self.owner, &self.enrollment.browser, SOURCE)
            .await
            .unwrap();
        let response = self
            .token
            .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        (pending.transaction, response)
    }

    fn request(&self, transaction: Uuid) -> PasskeyAuthenticationRequest {
        PasskeyAuthenticationRequest {
            realm: self.enrollment.realm,
            transaction,
            browser: self.enrollment.browser.verifier(),
            source: [1; 32],
        }
    }

    async fn proof(
        &self,
        transaction: Uuid,
        response: &PasskeyAuthenticationResponse,
    ) -> VerifiedPasskeyAuthentication {
        let f = &self.enrollment;
        let (state, credential) = f
            .store
            .load_authentication(
                &self.request(transaction),
                f.service.rp_id(),
                response.raw_id.as_slice(),
            )
            .await
            .unwrap();
        f.service
            .verify_authentication(response, state, credential)
            .unwrap()
    }
}

async fn authentication_count(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='passkey_authenticated'")
        .fetch_one(pool)
        .await
        .unwrap()
}
