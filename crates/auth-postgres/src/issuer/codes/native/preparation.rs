use crate::{sessions::FreshSessionAuthorization, unavailable};
use auth_core::{
    Error, IssuerAuthority, IssuerAuthorizationRequest, IssuerNativeConsentData,
    IssuerNativeRefreshPolicy, Result,
};
use sqlx::{Postgres as Pg, Transaction};

/// Caller holds current client/policy, source, owner and the fresh initiating session.
pub(in crate::issuer::codes) async fn absolute_cap(
    tx: &mut Transaction<'_, Pg>,
    authority: &IssuerAuthority,
    caller: &FreshSessionAuthorization,
) -> Result<i64> {
    sqlx::query_scalar("SELECT (extract(epoch FROM expires_at)*1000000)::bigint FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3 AND revoked_at IS NULL")
        .bind(authority.realm()).bind(caller.user).bind(caller.session).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)
}
pub(in crate::issuer::codes) async fn attach(
    tx: &mut Transaction<'_, Pg>,
    request: &IssuerAuthorizationRequest,
    policy: &IssuerNativeRefreshPolicy,
    caller: &FreshSessionAuthorization,
    prepared: i64,
) -> Result<IssuerNativeConsentData> {
    let source_cap = absolute_cap(tx, request.authority(), caller).await?;
    let grant_expiry = policy.grant_expires_at_us(prepared, source_cap)?;
    sqlx::query("UPDATE auth_issuer_authorizations SET native_refresh=true,expires_at_us=least(expires_at_us,$3) WHERE realm_id=$1 AND id=$2 AND status='pending'")
        .bind(request.authority().realm()).bind(request.id()).bind(grant_expiry).execute(&mut **tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO auth_issuer_native_consents(realm_id,authorization_id,issuer,client_id,client_revision,user_id,session_id,policy_revision,lifetime_seconds,idle_seconds,prepared_at_us,source_absolute_cap_us,grant_expires_at_us) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
        .bind(request.authority().realm()).bind(request.id()).bind(request.authority().issuer())
        .bind(request.client().client()).bind(request.client().revision()).bind(caller.user).bind(caller.session)
        .bind(policy.revision()).bind(i64::from(policy.lifetime_seconds())).bind(i64::from(policy.idle_seconds()))
        .bind(prepared).bind(source_cap).bind(grant_expiry).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(IssuerNativeConsentData {
        policy: policy.clone(),
        prepared_at_us: prepared,
        source_absolute_cap_us: source_cap,
        grant_expires_at_us: grant_expiry,
        approved_at_us: None,
    })
}
