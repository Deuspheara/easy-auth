//! Representative pre-0029 sessions/audit use original columns, without current writers.
use auth_core::Secret;
use sqlx::PgPool;
use uuid::Uuid;

use super::legacy::LegacySession;

pub(crate) async fn seed_session(pool: &PgPool, realm: Uuid, email: &str) -> LegacySession {
    let user_id:Uuid=sqlx::query_scalar("INSERT INTO auth_users(realm_id,id,email) VALUES ($1,$2,$3) ON CONFLICT (realm_id,email) DO UPDATE SET email=EXCLUDED.email RETURNING id")
        .bind(realm).bind(Uuid::new_v4()).bind(email).fetch_one(pool).await.unwrap();
    let session_id = Uuid::new_v4();
    let secret = Secret::generate().unwrap();
    sqlx::query("INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authentication_method) VALUES ($1,$2,$3,$4,'email')")
        .bind(realm)
        .bind(session_id)
        .bind(user_id)
        .bind(secret.verifier().as_slice())
        .execute(pool)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO auth_audit(realm_id,user_id,kind,schema_version,session_id) VALUES ($1,$2,'email_authenticated',1,$3)",
    )
    .bind(realm)
    .bind(user_id)
    .bind(session_id)
    .execute(pool)
    .await
    .unwrap();
    LegacySession {
        user_id,
        session_id,
        secret,
    }
}
