mod admission;
mod migration;
mod policy;
mod sessions;
mod waiting;

use crate::support::realm;
use auth_core::Secret;
use easy_auth_postgres::Postgres;
use sqlx::PgPool;
use uuid::Uuid;

struct Fixture {
    pool: PgPool,
    store: Postgres,
    realm: Uuid,
    user: Uuid,
}

impl Fixture {
    async fn new(pool: PgPool, email: Option<&str>) -> Self {
        let (store, realm) = realm(pool.clone()).await;
        let user = Uuid::new_v4();
        sqlx::query(
            r#"
            INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy)
            VALUES ($1,$2,$3,CASE WHEN $3::text IS NULL THEN NULL ELSE clock_timestamp() END,
                'Example person','passkey_required')
            "#,
        )
        .bind(realm).bind(user).bind(email).execute(&pool).await.unwrap();
        Self {
            pool,
            store,
            realm,
            user,
        }
    }

    // Storage-policy fixture, not evidence of a successful authenticator ceremony.
    async fn session(&self, method: &str) -> (Secret, Uuid) {
        let secret = Secret::generate().unwrap();
        let id = Uuid::new_v4();
        sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,$5)")
            .bind(self.realm).bind(id).bind(self.user)
            .bind(secret.verifier().as_slice()).bind(method).execute(&self.pool).await.unwrap();
        (secret, id)
    }
}
