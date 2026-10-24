use crate::{Error, Result, unavailable};
use auth_core::IssuerNativeConsumerPolicy;
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Acquire both client rows in the same immutable-ID order before full-definition
/// or credential checks. Config and reads share this order; no operation acquires
/// an audience client after holding a consumer policy/source/owner/family lock.
pub(in crate::issuer::native_refresh) async fn lock_clients(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    consumer: Uuid,
    audience: Uuid,
) -> Result<()> {
    let mut ids = vec![consumer, audience];
    ids.sort_unstable();
    ids.dedup();
    for id in ids {
        sqlx::query("SELECT id FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2 FOR UPDATE")
            .bind(realm)
            .bind(id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?;
    }
    Ok(())
}
pub(in crate::issuer::native_refresh) async fn lock_policy(
    tx: &mut Transaction<'_, Postgres>,
    policy: &IssuerNativeConsumerPolicy,
    require_enabled: bool,
) -> Result<()> {
    let enabled:Option<bool>=sqlx::query_scalar("SELECT enabled FROM auth_issuer_native_consumers WHERE realm_id=$1 AND issuer=$2 AND consumer_id=$3 AND audience_id=$4 AND revision=$5 AND consumer_revision=$6 AND audience_revision=$7 FOR UPDATE")
        .bind(policy.authority().realm()).bind(policy.authority().issuer())
        .bind(policy.consumer().client()).bind(policy.audience().client()).bind(policy.revision())
        .bind(policy.consumer().revision()).bind(policy.audience().revision())
        .fetch_optional(&mut **tx).await.map_err(unavailable)?;
    if enabled.is_none() || (require_enabled && enabled != Some(true)) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
