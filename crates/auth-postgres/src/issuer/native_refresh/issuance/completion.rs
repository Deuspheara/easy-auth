use super::writing;
use crate::{
    Postgres,
    issuer::{
        authentication, codes::native::redemption::NativeCodeCandidate, native_refresh::policy,
        signing,
    },
    unavailable,
};
use auth_core::{
    IssuerNativeSignedCode, IssuerNativeTokenCommit, IssuerTokenError, IssuerTokenResult,
};

const MIN_TOKEN_REMAINING_US: i64 = 1_000_000;

pub(super) async fn commit(
    store: &Postgres,
    signed: &IssuerNativeSignedCode<'_>,
) -> IssuerTokenResult<IssuerNativeTokenCommit> {
    let request = signed.redemption();
    let candidate = NativeCodeCandidate::read(store, request).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    let candidate = candidate.ok_or(IssuerTokenError::InvalidGrant)?;
    if candidate.consent().policy != signed.consent().policy {
        return Err(IssuerTokenError::InvalidGrant);
    }
    policy::lock(&mut tx, &signed.consent().policy, true).await?;
    let current = signing::lock_current(&mut tx, request.authority).await?;
    if current != *signed.signing() {
        return Err(IssuerTokenError::Unavailable);
    }
    let locked = candidate.lock(&mut tx, request).await?;
    if !locked.matches(&mut tx, signed).await?
        || signed.expires_at_us() > locked.expires_at_us()
        || signed.expires_at_us() > signed.grant().expires_at_us
        || signed.expires_at_us() > current.publication().sign_until_us()
    {
        return Err(IssuerTokenError::InvalidGrant);
    }
    let now = signing::now(&mut tx).await?;
    if now >= locked.expires_at_us() || now < signed.grant().issued_at_us {
        return Err(IssuerTokenError::InvalidGrant);
    }
    locked.quota(&mut tx, request, now).await?;
    let idle_until = writing::family(&mut tx, signed, now).await?;
    writing::access(&mut tx, signed).await?;
    locked.consume(&mut tx, request, now).await?;
    writing::created(&mut tx, signed).await?;
    // Last SQL after every authority/audit write. No signature/source/key lookup follows.
    let final_now = signing::now(&mut tx).await?;
    if final_now >= current.publication().sign_until_us() {
        return Err(IssuerTokenError::Unavailable);
    }
    if final_now >= locked.expires_at_us()
        || signed.expires_at_us().saturating_sub(final_now) < MIN_TOKEN_REMAINING_US
        || idle_until.saturating_sub(final_now) < MIN_TOKEN_REMAINING_US
    {
        return Err(IssuerTokenError::InvalidGrant);
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(IssuerNativeTokenCommit {
        committed_at_us: final_now,
        refresh_expires_at_us: idle_until,
    })
}
