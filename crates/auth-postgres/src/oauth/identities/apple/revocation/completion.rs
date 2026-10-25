use crate::{Postgres, unavailable};
use auth_core::{
    AppleGrantRevocationJob, AppleRevocationConfirmation, AppleRevocationFailure, OAuthConnection,
    Result,
};
use sqlx::Transaction;

async fn lock<'a>(
    store: &'a Postgres,
    source: &OAuthConnection,
    job: &AppleGrantRevocationJob,
) -> Result<Option<Transaction<'a, sqlx::Postgres>>> {
    if !super::matches(source, job) {
        return Ok(None);
    }
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    let found: Option<i32> = sqlx::query_scalar(
        r#"
        SELECT 1 FROM auth_apple_grants
        WHERE realm_id=$1 AND id=$2 AND connection_id=$3 AND client_id=$4
          AND provider_client=$5 AND state='leased' AND lease_id=$6 AND version=$7
          AND (extract(epoch FROM lease_until)*1000000)::bigint=$8
        FOR UPDATE
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
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    if found.is_none() || !live(&mut tx, job).await? {
        return Ok(None);
    }
    Ok(Some(tx))
}
async fn live(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    job: &AppleGrantRevocationJob,
) -> Result<bool> {
    sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint >= $1 AND (extract(epoch FROM clock_timestamp())*1000000)::bigint < $2")
        .bind(job.claimed_us()).bind(job.until_us()).fetch_one(&mut **tx).await.map_err(unavailable)
}
pub(super) async fn confirm(
    store: &Postgres,
    source: &OAuthConnection,
    confirmation: AppleRevocationConfirmation,
) -> Result<bool> {
    let job = confirmation.job();
    let Some(mut tx) = lock(store, source, job).await? else {
        return Ok(false);
    };
    sqlx::query(
        r#"
        UPDATE auth_apple_grants
        SET state='completed',ciphertext=NULL,key_id=NULL,lease_id=NULL,lease_until=NULL,
            finished_at=clock_timestamp(),failure=NULL,version=version+1
        WHERE realm_id=$1 AND id=$2
        "#,
    )
    .bind(source.realm())
    .bind(job.envelope().binding().grant())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    // Recheck after every row/table write wait; a pre-wait WHERE clock alone
    // would permit an unchanged locked row to acknowledge after its original cap.
    if !live(&mut tx, job).await? {
        return Ok(false);
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(true)
}
pub(super) async fn defer(
    store: &Postgres,
    source: &OAuthConnection,
    job: &AppleGrantRevocationJob,
    failure: AppleRevocationFailure,
) -> Result<bool> {
    let Some(mut tx) = lock(store, source, job).await? else {
        return Ok(false);
    };
    let failure = match failure {
        AppleRevocationFailure::Transport => "transport",
        AppleRevocationFailure::Provider => "provider",
        AppleRevocationFailure::Configuration => "configuration",
        AppleRevocationFailure::Unavailable => "unavailable",
    };
    sqlx::query(
        r#"
        UPDATE auth_apple_grants
        SET state=CASE WHEN attempts=8 THEN 'failed' ELSE 'pending' END,
            lease_id=NULL,lease_until=NULL,failure=$3,version=version+1,
            next_attempt_at=least(expires_at,clock_timestamp()+make_interval(
                secs=>least(3600,30*(1<<least(attempts-1,7)))::double precision))
        WHERE realm_id=$1 AND id=$2
        "#,
    )
    .bind(source.realm())
    .bind(job.envelope().binding().grant())
    .bind(failure)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    if !live(&mut tx, job).await? {
        return Ok(false);
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(true)
}
