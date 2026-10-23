use super::state::Family;
use crate::{audit, unavailable};
use auth_core::{
    AuditEvent, IssuerNativeCredentialAction, IssuerNativeCredentialEvent,
    IssuerNativeCredentialKind, IssuerNativeRotationRequest, IssuerSigningSnapshot,
    IssuerTokenError, IssuerTokenResult,
};
use sqlx::{Postgres as Pg, Transaction};

pub(super) async fn rotate(
    tx: &mut Transaction<'_, Pg>,
    request: &IssuerNativeRotationRequest<'_>,
    family: &Family,
    key: &IssuerSigningSnapshot,
    now: i64,
    access_expiry: i64,
    idle_until: i64,
) -> IssuerTokenResult<i64> {
    let credential = &request.credential;
    let next = family
        .generation
        .checked_add(1)
        .ok_or(IssuerTokenError::Unavailable)?;
    let spent=sqlx::query("UPDATE auth_issuer_native_refresh_tokens SET spent_at_us=$6 WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND family_id=$4 AND token_hash=$5 AND spent_at_us IS NULL")
        .bind(credential.authority.realm()).bind(credential.authority.issuer()).bind(credential.client.client()).bind(family.origin.id).bind(credential.token.as_slice()).bind(now)
        .execute(&mut **tx).await.map_err(unavailable)?.rows_affected();
    if spent != 1 {
        return Err(IssuerTokenError::InvalidGrant);
    }
    sqlx::query("UPDATE auth_issuer_native_families SET generation=$3,idle_until_us=$4 WHERE realm_id=$1 AND id=$2")
        .bind(family.origin.realm_id).bind(family.origin.id).bind(next).bind(idle_until).execute(&mut **tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO auth_issuer_native_refresh_tokens(realm_id,issuer,family_id,authorization_id,client_id,user_id,generation,token_hash,issued_at_us) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
        .bind(family.origin.realm_id).bind(&family.origin.issuer).bind(family.origin.id).bind(family.origin.authorization_id).bind(family.origin.client_id).bind(family.origin.user_id)
        .bind(next).bind(request.refresh.as_slice()).bind(now).execute(&mut **tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO auth_issuer_access_tokens(realm_id,issuer,id,authorization_id,client_id,user_id,session_id,subject,key_id,access_hash,issued_at_us,expires_at_us,native_refresh,native_family_id,native_generation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true,$13,$14)")
        .bind(family.origin.realm_id).bind(&family.origin.issuer).bind(request.access_id).bind(family.origin.authorization_id).bind(family.origin.client_id)
        .bind(family.origin.user_id).bind(family.origin.session_id).bind(family.origin.subject).bind(key.publication().key().id()).bind(request.access.as_slice()).bind(now)
        .bind(access_expiry).bind(family.origin.id).bind(next).execute(&mut **tx).await.map_err(unavailable)?;
    audit::record(
        tx,
        family.origin.realm_id,
        AuditEvent::IssuerNativeCredential(IssuerNativeCredentialEvent {
            user_id: family.origin.user_id,
            client_id: family.origin.client_id,
            authorization_id: family.origin.authorization_id,
            family_id: family.origin.id,
            generation: next,
            action: IssuerNativeCredentialAction::Rotated,
            credential: IssuerNativeCredentialKind::RefreshToken,
        }),
    )
    .await?;
    Ok(next)
}
