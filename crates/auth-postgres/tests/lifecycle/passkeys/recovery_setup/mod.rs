mod boundaries;
mod concurrency;
mod isolation;
mod migration;
mod waiting;

use super::{Fixture, SOURCE};
use auth_core::{
    Error, PasskeyRecoverySetup, PasskeyRecoverySetupRepository, PasskeyRecoverySetupRequest,
    Repository, Secret,
};
use sqlx::PgPool;
use uuid::Uuid;
use webauthn_authenticator_rs::softtoken::SoftToken;

struct Setup {
    f: Fixture,
    pool: PgPool,
    flow: PasskeyRecoverySetup,
    owner: Uuid,
    weak: Secret,
    token: SoftToken,
}

impl Setup {
    async fn new(pool: PgPool, email_free: bool) -> Self {
        let mut f = Fixture::new(pool.clone()).await;
        let owner = f
            .store
            .authenticate(f.realm, f.session.verifier())
            .await
            .unwrap()
            .id;
        let (id, response, mut token) = f.begin_with_token().await;
        f.enrollment
            .finish(&f.session, &f.browser, SOURCE, id, &response)
            .await
            .unwrap();
        let proven = f.sign_in_with_key(&mut token).await;
        let weak = std::mem::replace(&mut f.session, proven);
        if email_free {
            // Stored account-model fixture; method/time originate from a real assertion.
            sqlx::query("UPDATE auth_users SET email=NULL,email_verified_at=NULL,display_name='Recovery owner',authentication_policy='passkey_required' WHERE realm_id=$1 AND id=$2")
                .bind(f.realm).bind(owner).execute(&pool).await.unwrap();
        }
        let flow = PasskeyRecoverySetup::new(f.realm, f.service.clone(), f.store.clone());
        Self {
            f,
            pool,
            flow,
            owner,
            weak,
            token,
        }
    }

    fn request(&self) -> PasskeyRecoverySetupRequest {
        PasskeyRecoverySetupRequest {
            realm: self.f.realm,
            session: self.f.session.verifier(),
            rp_id: self.f.service.rp_id().into(),
            source: [23; 32],
        }
    }

    async fn snapshot(&self) -> Vec<String> {
        let mut rows = Vec::new();
        for table in [
            "auth_users",
            "auth_sessions",
            "auth_passkeys",
            "auth_passkey_recovery_codes",
            "auth_passkey_recovery_setups",
            "auth_audit",
            "auth_security_notifications",
        ] {
            rows.push(sqlx::query_scalar(&format!("SELECT coalesce(string_agg(row_to_json(t)::text,E'\\n' ORDER BY row_to_json(t)::text),'') FROM {table} t WHERE realm_id=$1"))
                .bind(self.f.realm).fetch_one(&self.pool).await.unwrap());
        }
        rows
    }

    async fn unchanged(&self, before: Vec<String>) {
        // Admission is deliberately durable and excluded; never print secret-bearing rows.
        assert!(
            self.snapshot().await == before,
            "rejected setup must preserve all authority and durable effects"
        );
    }

    async fn active(&self) -> Option<(Uuid, Vec<u8>)> {
        sqlx::query_as("SELECT version,code_hash FROM auth_passkey_recovery_codes WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3")
            .bind(self.f.realm).bind(self.owner).bind(self.f.service.rp_id()).fetch_optional(&self.pool).await.unwrap()
    }

    async fn counts(&self) -> (i64, i64, i64) {
        sqlx::query_as("SELECT (SELECT count(*) FROM auth_passkey_recovery_setups WHERE realm_id=$1),(SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='passkey_recovery_configured'),(SELECT count(*) FROM auth_security_notifications WHERE realm_id=$1 AND kind='passkey_recovery_changed')")
            .bind(self.f.realm).fetch_one(&self.pool).await.unwrap()
    }
}
