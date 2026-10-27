use crate::{Postgres, unavailable};
use auth_core::{
    AppleGrantBinding, AppleGrantEnvelope, AppleGrantRevocationJob, Error, OAuthConnection, Result,
};
use sqlx::Row;
use uuid::Uuid;

pub(super) async fn claim(
    store: &Postgres,
    source: &OAuthConnection,
) -> Result<Option<AppleGrantRevocationJob>> {
    store.maintain_apple_grants(source.realm()).await?;
    let lease = Uuid::new_v4();
    let row=sqlx::query(r#"
        WITH observed AS MATERIALIZED (SELECT clock_timestamp() AS now),
        due AS (SELECT g.id FROM auth_apple_grants g,observed o
            WHERE g.realm_id=$1 AND g.connection_id=$2 AND g.client_id=$3 AND g.provider_client=$4
              AND g.attempts<8 AND g.expires_at>o.now
              AND ((g.state='pending' AND g.next_attempt_at<=o.now) OR (g.state='leased' AND g.lease_until<=o.now))
            ORDER BY g.next_attempt_at,g.id FOR UPDATE OF g SKIP LOCKED LIMIT 1)
        UPDATE auth_apple_grants g SET state='leased',attempts=attempts+1,lease_id=$5,
            lease_until=least(g.expires_at,o.now+interval '60 seconds'),version=version+1
        FROM due,observed o WHERE g.realm_id=$1 AND g.id=due.id
        RETURNING g.id,g.connection_id,g.client_id,g.binding_identity_id,g.key_id,g.ciphertext,g.version,
            (extract(epoch FROM o.now)*1000000)::bigint AS claimed_us,
            (extract(epoch FROM g.lease_until)*1000000)::bigint AS until_us
        "#).bind(source.realm()).bind(source.connection()).bind(source.client()).bind(source.provider_client())
        .bind(lease).fetch_optional(&store.pool).await.map_err(unavailable)?;
    row.map(|row| {
        let binding = AppleGrantBinding::new(
            source.realm(),
            row.try_get("connection_id").map_err(unavailable)?,
            row.try_get("client_id").map_err(unavailable)?,
            row.try_get("binding_identity_id").map_err(unavailable)?,
            row.try_get("id").map_err(unavailable)?,
        )?;
        let envelope = AppleGrantEnvelope::restore(
            binding,
            row.try_get("key_id").map_err(unavailable)?,
            row.try_get("ciphertext").map_err(unavailable)?,
        )?;
        AppleGrantRevocationJob::restore(
            envelope,
            lease,
            row.try_get("version").map_err(unavailable)?,
            row.try_get("claimed_us").map_err(unavailable)?,
            row.try_get("until_us").map_err(unavailable)?,
        )
    })
    .transpose()
}
pub(super) async fn check(
    store: &Postgres,
    source: &OAuthConnection,
    job: &AppleGrantRevocationJob,
) -> Result<i64> {
    if !super::matches(source, job) {
        return Err(Error::Unauthorized);
    }
    sqlx::query_scalar(
        r#"
        SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint
        FROM auth_apple_grants
        WHERE realm_id=$1 AND id=$2 AND connection_id=$3 AND client_id=$4
          AND provider_client=$5 AND state='leased' AND lease_id=$6 AND version=$7
          AND (extract(epoch FROM lease_until)*1000000)::bigint=$8
          AND lease_until>clock_timestamp() AND expires_at>clock_timestamp()
          AND (extract(epoch FROM clock_timestamp())*1000000)::bigint>=$9
        "#,
    )
    .bind(source.realm())
    .bind(job.envelope().binding().grant())
    .bind(source.connection())
    .bind(source.client())
    .bind(source.provider_client())
    .bind(job.lease())
    .bind(job.version())
    .bind(job.until_us())
    .bind(job.claimed_us())
    .fetch_optional(&store.pool)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)
}
