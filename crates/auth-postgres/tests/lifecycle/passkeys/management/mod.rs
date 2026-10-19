mod audit;
mod boundaries;
mod concurrency;
mod migration;
mod rollback;
mod waiting;

use super::{Fixture, ORIGIN, SOURCE};
use auth_core::{PasskeyInfo, PasskeyManagement, PasskeySignIn, Repository, Secret};
use sqlx::PgPool;
use uuid::Uuid;
use webauthn_authenticator_rs::{AuthenticatorBackend, softtoken::SoftToken};

struct Management {
    fixture: Fixture,
    pool: PgPool,
    flow: PasskeyManagement,
    owner: Uuid,
    session: Secret,
}

impl Management {
    async fn new(pool: PgPool, email_free: bool) -> Self {
        let fixture = Fixture::new(pool.clone()).await;
        let owner = fixture
            .store
            .authenticate(fixture.realm, fixture.session.verifier())
            .await
            .unwrap()
            .id;
        let flow = PasskeyManagement::new(
            fixture.realm,
            fixture.service.clone(),
            fixture.store.clone(),
        );
        let mut this = Self {
            fixture,
            pool,
            flow,
            owner,
            session: Secret::generate().unwrap(),
        };
        let (_, mut token) = this
            .add_key_with_session("First key", &this.fixture.session)
            .await;
        this.session = this.sign_in(&mut token).await;
        if email_free {
            // Storage policy fixture only; the session/key proof above is a real assertion.
            sqlx::query("UPDATE auth_users SET email=NULL,email_verified_at=NULL,display_name='Key owner',authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
                .bind(this.fixture.realm).bind(owner).execute(&this.pool).await.unwrap();
        }
        this
    }

    async fn add_key(&self, label: &str) -> (Uuid, SoftToken) {
        self.add_key_with_session(label, &self.session).await
    }

    async fn add_key_with_session(&self, label: &str, session: &Secret) -> (Uuid, SoftToken) {
        let f = &self.fixture;
        let pending = f
            .enrollment
            .begin(session, &f.browser, SOURCE, label)
            .await
            .unwrap();
        let (mut token, _) = SoftToken::new(true).unwrap();
        let response = token
            .perform_register(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        let id = f
            .enrollment
            .finish(session, &f.browser, SOURCE, pending.transaction, &response)
            .await
            .unwrap();
        (id, token)
    }

    async fn sign_in(&self, token: &mut SoftToken) -> Secret {
        let f = &self.fixture;
        let flow = PasskeySignIn::new(f.realm, f.service.clone(), f.store.clone());
        let pending = flow
            .begin_account(self.owner, &f.browser, SOURCE)
            .await
            .unwrap();
        let response = token
            .perform_auth(ORIGIN.parse().unwrap(), pending.options.public_key, 120_000)
            .unwrap();
        flow.finish(&f.browser, SOURCE, pending.transaction, &response)
            .await
            .unwrap()
    }

    async fn keys(&self) -> Vec<PasskeyInfo> {
        self.flow.list(&self.session, SOURCE).await.unwrap()
    }

    async fn key(&self, id: Uuid) -> PasskeyInfo {
        self.keys()
            .await
            .into_iter()
            .find(|key| key.id == id)
            .unwrap()
    }

    async fn snapshot(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for table in [
            "auth_users",
            "auth_passkeys",
            "auth_sessions",
            "auth_audit",
            "auth_security_notifications",
            "auth_passkey_enrollments",
            "auth_passkey_authentications",
            "auth_email_attachments",
        ] {
            rows.push(sqlx::query_scalar(&format!("SELECT coalesce(string_agg(row_to_json(t)::text,E'\\n' ORDER BY row_to_json(t)::text),'') FROM {table} t WHERE realm_id=$1"))
                .bind(self.fixture.realm).fetch_one(&self.pool).await.unwrap());
        }
        rows
    }

    async fn assert_unchanged(&self, before: Vec<String>) {
        assert!(
            self.snapshot().await == before,
            "failed management transaction must preserve all durable security effects"
        );
    }
}
