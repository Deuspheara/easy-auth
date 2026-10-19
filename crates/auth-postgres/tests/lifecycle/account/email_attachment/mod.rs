mod atomicity;
mod binding;
mod concurrency;
mod migration;
mod waiting;

use auth_core::{Repository, Secret};
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

struct Fixture {
    pool: PgPool,
    store: Postgres,
    realm: Uuid,
    user: Uuid,
    current: Secret,
    actor: Uuid,
}

impl Fixture {
    async fn new(pool: PgPool) -> Self {
        Self::in_realm(pool, Uuid::new_v4()).await
    }

    async fn in_realm(pool: PgPool, realm: Uuid) -> Self {
        let store = Postgres::new(pool.clone());
        store.ensure_realm(realm).await.unwrap();
        let user = Uuid::new_v4();
        sqlx::query("INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy) VALUES ($1,$2,NULL,NULL,'Person','passkey_required')")
            .bind(realm).bind(user).execute(&pool).await.unwrap();
        let current = Secret::generate().unwrap();
        let actor = Uuid::new_v4();
        // Storage-policy fixture; native signup separately proves real key possession.
        sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'passkey')")
            .bind(realm).bind(actor).bind(user).bind(current.verifier().as_slice()).execute(&pool).await.unwrap();
        Self {
            pool,
            store,
            realm,
            user,
            current,
            actor,
        }
    }

    async fn proof(&self, email: &str) -> (Secret, Secret) {
        let proof = Secret::generate().unwrap();
        let browser = Secret::generate().unwrap();
        self.store
            .begin_email_attachment(
                self.realm,
                self.current.verifier(),
                email,
                proof.verifier(),
                browser.verifier(),
            )
            .await
            .unwrap();
        (proof, browser)
    }

    async fn email(&self) -> Option<String> {
        sqlx::query_scalar("SELECT email FROM auth_users WHERE realm_id=$1 AND id=$2")
            .bind(self.realm)
            .bind(self.user)
            .fetch_one(&self.pool)
            .await
            .unwrap()
    }

    async fn audits(&self) -> i64 {
        sqlx::query_scalar(
            "SELECT count(*) FROM auth_audit WHERE realm_id=$1 AND kind='email_attached'",
        )
        .bind(self.realm)
        .fetch_one(&self.pool)
        .await
        .unwrap()
    }
}
