//! Upgrade fixtures use the original columns, never current repository writes against an old schema.
use auth_core::Secret;
use sqlx::PgPool;
use uuid::Uuid;

pub(crate) struct LegacySession {
    pub(crate) user_id: Uuid,
    pub(crate) session_id: Uuid,
    pub(crate) secret: Secret,
}

pub(crate) async fn seed_session(pool: &PgPool, realm: Uuid, email: &str) -> LegacySession {
    let user_id:Uuid=sqlx::query_scalar("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,$3) ON CONFLICT (realm_id,email) DO UPDATE SET email=EXCLUDED.email RETURNING id")
        .bind(realm).bind(Uuid::new_v4()).bind(email).fetch_one(pool).await.unwrap();
    let session_id = Uuid::new_v4();
    let secret = Secret::generate().unwrap();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash) VALUES ($1,$2,$3,$4)")
        .bind(realm)
        .bind(session_id)
        .bind(user_id)
        .bind(secret.verifier().as_slice())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO auth_audit(realm_id,user_id,kind) VALUES ($1,$2,'email_authenticated')",
    )
    .bind(realm)
    .bind(user_id)
    .execute(pool)
    .await
    .unwrap();
    LegacySession {
        user_id,
        session_id,
        secret,
    }
}
