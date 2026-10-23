use super::state::{Family, Refresh};
use crate::{
    Postgres, audit,
    issuer::{authentication, signing},
    unavailable,
};
use auth_core::{
    AuditEvent, IssuerNativeCredentialAction as Action, IssuerNativeCredentialEvent,
    IssuerNativeCredentialKind as Kind, IssuerNativeCredentialRequest, IssuerTokenError,
    IssuerTokenResult,
};
use sqlx::{Postgres as Pg, Transaction};

/// Serialization only, never owner authentication. Hold owner before family so
/// credential audit FKs cannot invert account erasure's owner->family order.
pub(super) async fn lock_owner(
    tx: &mut Transaction<'_, Pg>,
    family: &Family,
) -> IssuerTokenResult<bool> {
    let owner: Option<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR KEY SHARE")
            .bind(family.origin.realm_id)
            .bind(family.origin.user_id)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?;
    Ok(owner.is_some())
}
pub(super) async fn reduce(
    tx: &mut Transaction<'_, Pg>,
    family: &Family,
    generation: i64,
    credential: Kind,
    action: Action,
) -> IssuerTokenResult<()> {
    if family.revoked_at_us.is_some() {
        return Ok(());
    }
    let now = signing::now(tx).await?;
    sqlx::query("UPDATE auth_issuer_native_families SET revoked_at_us=$3 WHERE realm_id=$1 AND id=$2 AND revoked_at_us IS NULL")
        .bind(family.origin.realm_id).bind(family.origin.id).bind(now).execute(&mut **tx).await.map_err(unavailable)?;
    sqlx::query("UPDATE auth_issuer_access_tokens SET revoked_at_us=greatest($3,issued_at_us) WHERE realm_id=$1 AND native_family_id=$2 AND revoked_at_us IS NULL")
        .bind(family.origin.realm_id).bind(family.origin.id).bind(now).execute(&mut **tx).await.map_err(unavailable)?;
    audit::record(
        tx,
        family.origin.realm_id,
        AuditEvent::IssuerNativeCredential(IssuerNativeCredentialEvent {
            user_id: family.origin.user_id,
            client_id: family.origin.client_id,
            authorization_id: family.origin.authorization_id,
            family_id: family.origin.id,
            generation,
            action,
            credential,
        }),
    )
    .await?;
    Ok(())
}
pub(super) async fn revoke(
    store: &Postgres,
    request: &IssuerNativeCredentialRequest<'_>,
) -> IssuerTokenResult<()> {
    request.validate_client()?;
    let candidate = if let Some(family) = Family::refresh(store, request).await? {
        Some((family, Kind::RefreshToken))
    } else {
        Family::access(store, request)
            .await?
            .map(|(f, _)| (f, Kind::AccessToken))
    };
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    if let Some((snapshot, kind)) = candidate {
        revoke_candidate(&mut tx, request, &snapshot, kind).await?;
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(())
}

async fn revoke_candidate(
    tx: &mut Transaction<'_, Pg>,
    request: &IssuerNativeCredentialRequest<'_>,
    snapshot: &Family,
    kind: Kind,
) -> IssuerTokenResult<()> {
    if !lock_owner(tx, snapshot).await? {
        return Ok(());
    }
    let Some(family) = snapshot.lock(tx).await? else {
        return Ok(());
    };
    let generation=match kind {
        Kind::RefreshToken=>Refresh::lock(tx,request,family.origin.id).await?.map(|r|r.generation),
        Kind::AccessToken=>sqlx::query_scalar("SELECT native_generation FROM auth_issuer_access_tokens WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND native_family_id=$4 AND access_hash=$5 FOR UPDATE")
            .bind(request.authority.realm()).bind(request.authority.issuer()).bind(request.client.client()).bind(family.origin.id).bind(request.token.as_slice())
            .fetch_optional(&mut **tx).await.map_err(unavailable)?,
        Kind::AuthorizationCode=>None,
    };
    if let Some(generation) = generation {
        reduce(tx, &family, generation, kind, Action::Revoked).await?;
    }
    Ok(())
}
