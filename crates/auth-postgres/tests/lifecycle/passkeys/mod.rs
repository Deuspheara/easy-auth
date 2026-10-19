mod authentication;
mod authentication_protocol;
mod concurrency;
mod enrollment;
mod enrollment_authority;
mod limits;
mod management;
mod protocol;
mod signup;
mod waiting;
mod waiting_completion;

use crate::support::{realm, signed_in};
use auth_core::{
    PasskeyCreationOptions, PasskeyEnrollment, PasskeyEnrollmentRequest,
    PasskeyRegistrationResponse, PasskeyService, Secret,
};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use std::sync::Arc;
use url::Url;
use uuid::Uuid;
use webauthn_authenticator_rs::{
    AuthenticatorBackend, WebauthnAuthenticator, softtoken::SoftToken,
};

const ORIGIN: &str = "https://login.example.com";
const SOURCE: &str = "127.0.0.1";

struct Fixture {
    store: Arc<Postgres>,
    realm: Uuid,
    service: Arc<PasskeyService>,
    enrollment: PasskeyEnrollment,
    session: Secret,
    browser: Secret,
}

impl Fixture {
    async fn new(pool: PgPool) -> Self {
        let (store, realm) = realm(pool).await;
        let session = signed_in(&store, realm, "alice@example.com").await;
        let store = Arc::new(store);
        let service = Arc::new(PasskeyService::new(ORIGIN, "Example").unwrap());
        let enrollment = PasskeyEnrollment::new(realm, service.clone(), store.clone());
        Self {
            store,
            realm,
            service,
            enrollment,
            session,
            browser: Secret::generate().unwrap(),
        }
    }

    fn request(&self, transaction: Uuid) -> PasskeyEnrollmentRequest {
        PasskeyEnrollmentRequest {
            realm: self.realm,
            session: self.session.verifier(),
            browser: self.browser.verifier(),
            source: [1; 32],
            transaction,
        }
    }

    async fn begin(&self) -> (Uuid, PasskeyRegistrationResponse) {
        let (id, response, _) = self.begin_with_token().await;
        (id, response)
    }

    async fn begin_with_token(&self) -> (Uuid, PasskeyRegistrationResponse, SoftToken) {
        let pending = self
            .enrollment
            .begin(&self.session, &self.browser, SOURCE, "Security key")
            .await
            .unwrap();
        let (mut token, _) = SoftToken::new(true).unwrap();
        let response = token
            .perform_register(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        (pending.transaction, response, token)
    }

    async fn sign_in_with_key(&self, token: &mut SoftToken) -> Secret {
        use auth_core::Repository;
        let owner = self
            .store
            .authenticate(self.realm, self.session.verifier())
            .await
            .unwrap()
            .id;
        let flow =
            auth_core::PasskeySignIn::new(self.realm, self.service.clone(), self.store.clone());
        let pending = flow
            .begin_account(owner, &self.browser, SOURCE)
            .await
            .unwrap();
        let response = token
            .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        flow.finish(&self.browser, SOURCE, pending.transaction, &response)
            .await
            .unwrap()
    }
}

fn register(
    options: PasskeyCreationOptions,
    origin: &str,
    uv: bool,
) -> PasskeyRegistrationResponse {
    // The software token deliberately simulates user verification for offline tests only.
    let (token, _) = SoftToken::new(uv).unwrap();
    WebauthnAuthenticator::new(token)
        .do_registration(Url::parse(origin).unwrap(), options)
        .unwrap()
}
