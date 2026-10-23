use crate::{Error, Result, unavailable};
use auth_core::IssuerNativeRefreshPolicy;
use sqlx::{Postgres as Pg, Transaction};

/// Caller holds the exact current enabled client. Policy is always locked before
/// source/owner/session state; no operation may accept a request-selected policy.
pub(in crate::issuer) async fn lock(
    tx: &mut Transaction<'_, Pg>,
    policy: &IssuerNativeRefreshPolicy,
    require_enabled: bool,
) -> Result<()> {
    let enabled: Option<bool> = sqlx::query_scalar(
        "SELECT enabled FROM auth_issuer_native_refresh_policies WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND revision=$4 AND client_revision=$5 AND lifetime_seconds=$6 AND idle_seconds=$7 FOR UPDATE",
    ).bind(policy.authority().realm()).bind(policy.authority().issuer())
        .bind(policy.client().client()).bind(policy.revision()).bind(policy.client().revision())
        .bind(i64::from(policy.lifetime_seconds())).bind(i64::from(policy.idle_seconds()))
        .fetch_optional(&mut **tx).await.map_err(unavailable)?;
    if enabled.is_none() || (require_enabled && enabled != Some(true)) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
