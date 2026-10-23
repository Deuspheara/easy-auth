use super::state::{self, AccessCandidate};
use crate::{
    Postgres,
    issuer::{authentication, signing},
    unavailable,
};
use auth_core::{
    Error, IssuerAccessData, IssuerTokenError, IssuerTokenResult, IssuerTokenStatusRequest,
};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct OriginalGrant {
    client_revision: Uuid,
    authentication_method: String,
    authenticated_at_us: i64,
    status: String,
    session_cap_us: i64,
    expires_at_us: i64,
    code_expires_at_us: Option<i64>,
}
pub(super) async fn inspect(
    store: &Postgres,
    request: &IssuerTokenStatusRequest<'_>,
) -> IssuerTokenResult<Option<IssuerAccessData>> {
    request.validate_introspection()?;
    // Snapshot chooses lock order only and opens no extra pool connection while
    // transaction locks are held. Credential comparison still precedes every result.
    let candidate = AccessCandidate::read(store, request).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    let Some(candidate) = candidate else {
        return Ok(None);
    };
    if candidate.original.revoked_at_us.is_some()
        || !signing::lock_retained_key(
            &mut tx,
            request.authority,
            candidate.original.key_id,
            candidate.original.issued_at_us,
            candidate.original.expires_at_us,
        )
        .await?
    {
        return Ok(None);
    }
    let caller = match candidate.owner.lock(&mut tx).await {
        Ok(caller) => caller,
        Err(Error::Unauthorized) => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let Some(locked) = state::locked_row(&mut tx, request).await? else {
        return Ok(None);
    };
    if locked != candidate.original
        || locked.revoked_at_us.is_some()
        || locked.user_id != caller.user
        || locked.session_id != caller.session
    {
        return Ok(None);
    }
    let original: Option<OriginalGrant> = sqlx::query_as("SELECT client_revision,authentication_method,authenticated_at_us,status,session_cap_us,expires_at_us,code_expires_at_us FROM auth_issuer_authorizations WHERE realm_id=$1 AND id=$2 FOR SHARE")
        .bind(request.authority.realm()).bind(locked.authorization_id).fetch_optional(&mut *tx).await.map_err(unavailable)?;
    let Some(original) = original else {
        return Ok(None);
    };
    if original.client_revision != request.client.revision()
        || original.authentication_method != caller.method
        || original.authenticated_at_us != caller.authenticated_at_us
        || original.status != "consumed"
    {
        return Ok(None);
    }
    let original_cap = original
        .code_expires_at_us
        .ok_or(IssuerTokenError::Unavailable)?
        .min(original.session_cap_us)
        .min(original.expires_at_us);
    if locked.expires_at_us > original_cap {
        return Ok(None);
    }
    // Last SQL after every source/owner/session/access-row wait. A previous read
    // cannot make an expired token active, and inspection does not touch idle time.
    let now: i64 =
        sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
    if now < locked.issued_at_us
        || now >= locked.expires_at_us
        || now >= caller.deadline.expires_us()
    {
        return Ok(None);
    }
    let data = IssuerAccessData {
        realm: request.authority.realm(),
        issuer: request.authority.issuer().to_owned(),
        client: request.client.client(),
        subject: locked.subject,
        issued_at_us: locked.issued_at_us,
        expires_at_us: locked.expires_at_us,
        checked_at_us: now,
    };
    tx.commit().await.map_err(unavailable)?;
    Ok(Some(data))
}
