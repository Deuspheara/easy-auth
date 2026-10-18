mod concurrency;
mod events;
mod migration;
mod ownership;
mod rollback;
mod shape;

use sqlx::PgPool;
use uuid::Uuid;

async fn session_id(pool: &PgPool, verifier: [u8; 32]) -> Uuid {
    sqlx::query_scalar("SELECT id FROM auth_sessions WHERE token_hash=$1")
        .bind(verifier.as_slice())
        .fetch_one(pool)
        .await
        .unwrap()
}
async fn rows(pool: &PgPool, realm: Uuid) -> Vec<String> {
    sqlx::query_scalar("SELECT to_jsonb(a)::text FROM auth_audit a WHERE realm_id=$1 ORDER BY id")
        .bind(realm)
        .fetch_all(pool)
        .await
        .unwrap()
}
