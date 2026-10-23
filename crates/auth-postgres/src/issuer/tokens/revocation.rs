use crate::{Postgres, issuer::authentication, unavailable};
use auth_core::{IssuerTokenError, IssuerTokenResult, IssuerTokenStatusRequest};

pub(super) async fn revoke(
    store: &Postgres,
    request: &IssuerTokenStatusRequest<'_>,
) -> IssuerTokenResult<()> {
    request.validate_client()?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    // No owner/source locks are needed to reduce only this exact credential's
    // authority. This also permits revocation after logout/expiry/key disable.
    sqlx::query("UPDATE auth_issuer_access_tokens SET revoked_at_us=(extract(epoch FROM clock_timestamp())*1000000)::bigint WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND access_hash=$4 AND revoked_at_us IS NULL")
        .bind(request.authority.realm()).bind(request.authority.issuer()).bind(request.client.client()).bind(request.token.as_slice())
        .execute(&mut *tx).await.map_err(unavailable)?;
    tx.commit().await.map_err(unavailable).map_err(Into::into)
}
