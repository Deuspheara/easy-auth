use super::ownership;
use crate::{Postgres, locking::lock_email, unavailable};
use auth_core::{Error, Result, Verifier};
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn begin_email_attachment(
        &self,
        realm: Uuid,
        current: Verifier,
        email: &str,
        token: Verifier,
        browser: Verifier,
    ) -> Result<()> {
        let user = ownership::lookup(&self.pool, realm, current).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_email(&mut tx, realm, email).await?;
        let session = ownership::lock_fresh(&mut tx, realm, user, current).await?;
        // Share target-mailbox admission with magic-link issuance, including
        // occupied targets. No target-owner lookup affects initiation or delivery.
        let admitted: Option<i32> = sqlx::query_scalar(
            r#"
            INSERT INTO auth_rate_buckets(realm_id,dimension,key_hash,window_id,attempts)
            VALUES ($1,'email',sha256($2),floor(extract(epoch FROM clock_timestamp())/600)::bigint,1)
            ON CONFLICT (realm_id,dimension,key_hash,window_id) DO UPDATE
            SET attempts=auth_rate_buckets.attempts+1 WHERE auth_rate_buckets.attempts<5
            RETURNING attempts
            "#,
        ).bind(realm).bind(email.as_bytes()).fetch_optional(&mut *tx).await.map_err(unavailable)?;
        admitted.ok_or(Error::RateLimited)?;
        // A new request cancels the old one; pending state is bounded to one per owner.
        sqlx::query(
            r#"
            INSERT INTO auth_email_attachments(realm_id,user_id,session_id,email,token_hash,browser_hash)
            VALUES ($1,$2,$3,$4,$5,$6)
            ON CONFLICT (realm_id,user_id) DO UPDATE SET session_id=EXCLUDED.session_id,
              email=EXCLUDED.email,token_hash=EXCLUDED.token_hash,browser_hash=EXCLUDED.browser_hash,
              expires_at=clock_timestamp()+interval '5 minutes'
            "#,
        ).bind(realm).bind(user).bind(session).bind(email).bind(token.as_slice()).bind(browser.as_slice())
            .execute(&mut *tx).await.map_err(unavailable)?;
        crate::locking::fresh_session(&mut tx, realm, user, current).await?;
        tx.commit().await.map_err(unavailable)
    }
}
