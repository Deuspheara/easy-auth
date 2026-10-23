use super::super::{loading, state};
use crate::{
    Postgres,
    issuer::{authentication, codes::redemption_state::CodeCandidate},
    unavailable,
};
use auth_core::{
    IssuerCodeRedemption, IssuerTokenError, IssuerTokenPreparationData, IssuerTokenResult,
};

pub(super) async fn prepare(
    store: &Postgres,
    request: &IssuerCodeRedemption<'_>,
) -> IssuerTokenResult<IssuerTokenPreparationData> {
    let candidate = CodeCandidate::read(store, request).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    if !request.client.permits_redirect(request.redirect_uri) {
        return Err(IssuerTokenError::InvalidGrant);
    }
    // Current client -> issuer keys -> provider source/email/owner/session/code.
    // Every lock is released before any RSA operation.
    let signing = loading::lock_current(&mut tx, request.authority).await?;
    let locked = candidate
        .ok_or(IssuerTokenError::InvalidGrant)?
        .lock(&mut tx, request)
        .await?;
    let code_snapshot = locked.snapshot(&mut tx, request).await?;
    let now = state::now(&mut tx).await?;
    if now >= locked.expires_at_us() {
        return Err(IssuerTokenError::InvalidGrant);
    }
    if now >= signing.publication().sign_until_us() {
        return Err(IssuerTokenError::Unavailable);
    }
    let grant = locked.facts(now)?;
    tx.commit().await.map_err(unavailable)?;
    Ok(IssuerTokenPreparationData {
        signing,
        grant,
        code_snapshot,
    })
}
