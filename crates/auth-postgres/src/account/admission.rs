use crate::{Postgres, unavailable};
use auth_core::{Error, Result, Verifier};
use uuid::Uuid;

impl Postgres {
    pub(crate) async fn admit_user_action(
        &self,
        realm: Uuid,
        user: Uuid,
        source: Verifier,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        for (dimension, key, limit) in [
            ("sensitive_user", user.as_bytes().as_slice(), 10),
            ("sensitive_source", source.as_slice(), 40),
        ] {
            let admitted = sqlx::query_scalar::<_, i32>(
                r#"
                INSERT INTO auth_rate_buckets(realm_id,dimension,key_hash,window_id,attempts)
                VALUES ($1,$2,sha256($3),floor(extract(epoch FROM clock_timestamp())/600)::bigint,1)
                ON CONFLICT (realm_id,dimension,key_hash,window_id) DO UPDATE
                SET attempts=auth_rate_buckets.attempts+1
                WHERE auth_rate_buckets.attempts<$4
                RETURNING attempts
                "#,
            )
            .bind(realm)
            .bind(dimension)
            .bind(key)
            .bind(limit)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
            if admitted.is_none() {
                return Err(Error::RateLimited);
            }
        }
        tx.commit().await.map_err(unavailable)
    }
}
