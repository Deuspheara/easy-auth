use crate::locking::lock_email;
use crate::unavailable;
use auth_core::{Error, Result, Verifier};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Snapshot only selects the lock path; it does not authorize an operation.
pub(super) struct Owner {
    pub(super) user: Uuid,
    pub(super) email: Option<String>,
}

impl Owner {
    pub(super) async fn load(pool: &PgPool, realm: Uuid, current: Verifier) -> Result<Self> {
        let (user, email) = sqlx::query_as(
            r#"
            SELECT u.id,u.email FROM auth_users u
            JOIN auth_sessions s ON s.realm_id=u.realm_id AND s.user_id=u.id
            WHERE s.realm_id=$1 AND s.token_hash=$2
            "#,
        )
        .bind(realm)
        .bind(current.as_slice())
        .fetch_optional(pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        Ok(Self { user, email })
    }

    pub(super) async fn lock_fresh(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        current: Verifier,
    ) -> Result<Uuid> {
        let source = super::source::Source::lock(tx, realm, current).await?;
        // Never acquire an email lock after the user lock. An attachment/change
        // that wins first must invalidate this snapshot, including NULL -> email.
        if let Some(email) = &self.email {
            lock_email(tx, realm, email).await?;
        }
        sqlx::query_scalar::<_, Uuid>(
            r#"
            SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2
              AND email IS NOT DISTINCT FROM $3::text FOR UPDATE
            "#,
        )
        .bind(realm)
        .bind(self.user)
        .bind(&self.email)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        source.fresh_session(tx, realm, self.user, current).await
    }
}
