use super::{clock, redemption_state::CodeCandidate};
use crate::{Postgres, issuer::authentication, unavailable};
use auth_core::{IssuerCodeRedemption, IssuerGrantData, IssuerTokenError, IssuerTokenResult};

pub(super) async fn redeem(
    store: &Postgres,
    request: &IssuerCodeRedemption<'_>,
) -> IssuerTokenResult<IssuerGrantData> {
    // Snapshot reads choose lock order only. Missing codes never skip actual
    // current client authentication before invalid_grant.
    let candidate = CodeCandidate::read(store, request).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    if !request.client.permits_redirect(request.redirect_uri) {
        return Err(IssuerTokenError::InvalidGrant);
    }
    let locked = candidate
        .ok_or(IssuerTokenError::InvalidGrant)?
        .lock(&mut tx, request)
        .await?;
    let now = clock::now(&mut tx).await?;
    if now >= locked.expires_at_us() {
        return Err(IssuerTokenError::InvalidGrant);
    }
    let mut facts = locked.facts(now)?;
    locked.consume(&mut tx, request, now).await?;
    facts.issued_at_us = clock::now(&mut tx).await?;
    locked.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(facts)
}
