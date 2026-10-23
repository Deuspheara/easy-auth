use super::super::{loading, state};
use crate::{
    Postgres,
    issuer::{authentication, codes::redemption_state::CodeCandidate},
    unavailable,
};
use auth_core::{IssuerSignedCode, IssuerTokenError, IssuerTokenResult};

const MIN_TOKEN_REMAINING_US: i64 = 1_000_000;

pub(super) async fn commit(
    store: &Postgres,
    signed: &IssuerSignedCode<'_>,
) -> IssuerTokenResult<i64> {
    let request = signed.redemption();
    let candidate = CodeCandidate::read(store, request).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    if !request.client.permits_redirect(request.redirect_uri) {
        return Err(IssuerTokenError::InvalidGrant);
    }
    let current = loading::lock_current(&mut tx, request.authority).await?;
    if current != *signed.signing() {
        return Err(IssuerTokenError::Unavailable);
    }
    let locked = candidate
        .ok_or(IssuerTokenError::InvalidGrant)?
        .lock(&mut tx, request)
        .await?;
    if !locked.matches_grant(signed.grant())?
        || locked.snapshot(&mut tx, request).await? != signed.code_snapshot()
        || signed.expires_at_us() > locked.expires_at_us()
        || signed.expires_at_us() > signed.grant().expires_at_us
        || signed.expires_at_us() > current.publication().sign_until_us()
    {
        return Err(IssuerTokenError::InvalidGrant);
    }
    let now = state::now(&mut tx).await?;
    if now >= locked.expires_at_us() || signed.grant().issued_at_us > now {
        return Err(IssuerTokenError::InvalidGrant);
    }
    // The opaque core proof fixes exact claims from the original snapshot. Its
    // nonce/owner/session/method/time are never selected from HTTP input here.
    sqlx::query(
        r#"
        INSERT INTO auth_issuer_access_tokens(realm_id,issuer,id,authorization_id,client_id,
            user_id,session_id,subject,key_id,access_hash,issued_at_us,expires_at_us)
        VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
    "#,
    )
    .bind(request.authority.realm())
    .bind(request.authority.issuer())
    .bind(signed.token_id())
    .bind(signed.grant().authorization)
    .bind(request.client.client())
    .bind(signed.grant().owner)
    .bind(signed.grant().session)
    .bind(signed.grant().subject)
    .bind(current.publication().key().id())
    .bind(signed.access_verifier().as_slice())
    .bind(signed.grant().issued_at_us)
    .bind(signed.expires_at_us())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    locked.consume(&mut tx, request, now).await?;
    // Last SQL after every write/audit wait. Capture actual commit-admission time;
    // no signature, client/source lookup or lock acquisition follows it.
    let final_now = state::now(&mut tx).await?;
    if final_now >= current.publication().sign_until_us() {
        return Err(IssuerTokenError::Unavailable);
    }
    if final_now >= locked.expires_at_us()
        || signed.expires_at_us().saturating_sub(final_now) < MIN_TOKEN_REMAINING_US
    {
        return Err(IssuerTokenError::InvalidGrant);
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(final_now)
}
