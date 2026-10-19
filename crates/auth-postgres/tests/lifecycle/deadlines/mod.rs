mod credentials;
mod email;
mod gates;
mod lifecycle;
mod sessions;
mod touch;

use crate::support::{realm, signed_in};
use auth_core::{Repository, Secret};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

const EMAIL: &str = "deadline-owner@example.test";
struct Fixture {
    pool: PgPool,
    store: Postgres,
    realm: Uuid,
    session: Secret,
    actor: Uuid,
}
impl Fixture {
    async fn new(pool: PgPool) -> Self {
        let (store, realm) = realm(pool.clone()).await;
        let session = signed_in(&store, realm, EMAIL).await;
        let actor =
            sqlx::query_scalar("SELECT id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
                .bind(realm)
                .bind(session.verifier().as_slice())
                .fetch_one(&pool)
                .await
                .unwrap();
        Self {
            pool,
            store,
            realm,
            session,
            actor,
        }
    }
    async fn with_password(pool: PgPool) -> Self {
        let mut f = Self::new(pool).await;
        let replacement = Secret::generate().unwrap();
        f.store
            .enroll_password(
                f.realm,
                f.session.verifier(),
                "old-hash",
                replacement.verifier(),
            )
            .await
            .unwrap();
        f.session = replacement;
        f.actor =
            sqlx::query_scalar("SELECT id FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2")
                .bind(f.realm)
                .bind(f.session.verifier().as_slice())
                .fetch_one(&f.pool)
                .await
                .unwrap();
        f
    }
    async fn snapshot(&self) -> Vec<String> {
        let mut rows = Vec::new();
        // Fixed test-only identifiers. Snapshot all durable side effects, including
        // attribution, credential versions, notices and proof cleanup. Never print it.
        for table in [
            "auth_users",
            "auth_sessions",
            "auth_password_credentials",
            "auth_email_challenges",
            "auth_password_resets",
            "auth_email_changes",
            "auth_account_deletions",
            "auth_email_attachments",
            "auth_passkeys",
            "auth_passkey_enrollments",
            "auth_passkey_authentications",
            "auth_passkey_signups",
            "auth_rate_buckets",
            "auth_audit",
            "auth_security_notifications",
        ] {
            let row: String = sqlx::query_scalar(&format!(
                "SELECT coalesce(string_agg(row_to_json(t)::text,E'\\n' ORDER BY row_to_json(t)::text),'') FROM {table} t WHERE realm_id=$1"))
                .bind(self.realm).fetch_one(&self.pool).await.unwrap();
            rows.push(row);
        }
        rows
    }
    async fn assert_unchanged(&self, before: Vec<String>) {
        assert!(
            self.snapshot().await == before,
            "expired transaction must roll back all durable effects"
        );
    }
}
