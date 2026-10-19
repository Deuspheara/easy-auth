mod atomicity;
mod binding;
mod collisions;
mod limits;
mod migration;
mod protocol;
mod waiting;

use super::{ORIGIN, SOURCE};
use auth_core::{
    PasskeyAuthenticationResponse, PasskeyRegistrationResponse, PasskeyService, PasskeySignup,
    PasskeySignupRepository, PasskeySignupRequest, Repository, Secret,
    VerifiedPasskeyAuthentication,
};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::Arc;
use uuid::Uuid;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

struct Signup {
    pool: PgPool,
    store: Arc<Postgres>,
    realm: Uuid,
    service: Arc<PasskeyService>,
    flow: PasskeySignup,
    browser: Secret,
    token: SoftToken,
}

impl Signup {
    async fn new(pool: PgPool) -> Self {
        let (store, realm) = crate::support::realm(pool.clone()).await;
        let store = Arc::new(store);
        let service = Arc::new(PasskeyService::new(ORIGIN, "Example").unwrap());
        let flow = PasskeySignup::new(realm, service.clone(), store.clone());
        // Software proof/atomicity tests, not resident/native interoperability evidence.
        let (token, _) = SoftToken::new(true).unwrap();
        Self {
            pool,
            store,
            realm,
            service,
            flow,
            browser: Secret::generate().unwrap(),
            token,
        }
    }

    async fn registration(&mut self) -> (Uuid, PasskeyRegistrationResponse) {
        let pending = self
            .flow
            .begin("Example person", &self.browser, SOURCE)
            .await
            .unwrap();
        let response = self
            .token
            .perform_register(
                ORIGIN.parse().unwrap(),
                software_creation(pending.options).public_key,
                120_000,
            )
            .unwrap();
        (pending.transaction, response)
    }

    async fn assertion(&mut self) -> (Uuid, PasskeyAuthenticationResponse) {
        let (id, response) = self.registration().await;
        let pending = self
            .flow
            .finish_registration(&self.browser, SOURCE, id, &response)
            .await
            .unwrap();
        let response = self
            .token
            .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        (id, response)
    }

    fn request(&self, id: Uuid) -> PasskeySignupRequest {
        PasskeySignupRequest {
            realm: self.realm,
            transaction: id,
            browser: self.browser.verifier(),
            source: [1; 32],
        }
    }

    async fn proof(
        &self,
        id: Uuid,
        response: &PasskeyAuthenticationResponse,
    ) -> VerifiedPasskeyAuthentication {
        let (state, candidate) = self
            .store
            .load_signup_authentication(&self.request(id), self.service.rp_id())
            .await
            .unwrap();
        self.service
            .verify_authentication(response, state, candidate)
            .unwrap()
    }

    async fn durable_counts(&self) -> (i64, i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_users WHERE realm_id=$1),(SELECT count(*) FROM auth_passkeys WHERE realm_id=$1),(SELECT count(*) FROM auth_sessions WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1)")
            .bind(self.realm).fetch_one(&self.pool).await.unwrap()
    }
}

fn software_creation(
    mut options: auth_core::PasskeyCreationOptions,
) -> auth_core::PasskeyCreationOptions {
    let selection = options.public_key.authenticator_selection.as_mut().unwrap();
    assert!(
        selection.require_resident_key,
        "server must request residence"
    );
    // Pinned SoftToken explicitly rejects residence. Only its test client hint
    // changes; private challenge/RP/UV state and production verification are intact.
    // These tests prove real nonresident signatures/transactions, not residence.
    selection.require_resident_key = false;
    selection.resident_key = None;
    options
}
