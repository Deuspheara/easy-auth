use crate::{audit, unavailable};
use auth_core::{
    AuditEvent, IssuerNativeCredentialAction, IssuerNativeCredentialEvent,
    IssuerNativeCredentialKind, IssuerNativeSignedCode, IssuerTokenError, IssuerTokenResult,
};
use sqlx::{Postgres as Pg, Transaction};

/// Caller holds current client/policy/key/source/owner/session/code/sidecar.
/// Family identity, owner and bounds come only from the concrete signed tuple.
pub(super) async fn family(
    tx: &mut Transaction<'_, Pg>,
    signed: &IssuerNativeSignedCode<'_>,
    now: i64,
) -> IssuerTokenResult<i64> {
    let request = signed.redemption();
    let grant = signed.grant();
    let consent = signed.consent();
    let idle_until = now
        .checked_add(i64::from(consent.policy.idle_seconds()) * 1_000_000)
        .ok_or(IssuerTokenError::Unavailable)?
        .min(consent.grant_expires_at_us);
    sqlx::query("INSERT INTO auth_issuer_native_families(realm_id,issuer,id,authorization_id,client_id,client_revision,policy_revision,user_id,session_id,subject,authentication_method,authenticated_at_us,lifetime_seconds,idle_seconds,prepared_at_us,approved_at_us,source_absolute_cap_us,created_at_us,expires_at_us,idle_until_us) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)")
        .bind(request.authority.realm()).bind(request.authority.issuer()).bind(signed.family_id()).bind(grant.authorization)
        .bind(request.client.client()).bind(request.client.revision()).bind(consent.policy.revision()).bind(grant.owner).bind(grant.session).bind(grant.subject)
        .bind(&grant.authentication_method).bind(grant.authenticated_at_us).bind(i64::from(consent.policy.lifetime_seconds())).bind(i64::from(consent.policy.idle_seconds()))
        .bind(consent.prepared_at_us).bind(consent.approved_at_us.ok_or(IssuerTokenError::Unavailable)?).bind(consent.source_absolute_cap_us)
        .bind(grant.issued_at_us).bind(consent.grant_expires_at_us).bind(idle_until).execute(&mut **tx).await.map_err(unavailable)?;
    sqlx::query("INSERT INTO auth_issuer_native_refresh_tokens(realm_id,issuer,family_id,authorization_id,client_id,user_id,generation,token_hash,issued_at_us) VALUES ($1,$2,$3,$4,$5,$6,0,$7,$8)")
        .bind(request.authority.realm()).bind(request.authority.issuer()).bind(signed.family_id()).bind(grant.authorization)
        .bind(request.client.client()).bind(grant.owner).bind(signed.refresh_verifier().as_slice()).bind(now).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(idle_until)
}
pub(super) async fn access(
    tx: &mut Transaction<'_, Pg>,
    signed: &IssuerNativeSignedCode<'_>,
) -> IssuerTokenResult<()> {
    let request = signed.redemption();
    let grant = signed.grant();
    sqlx::query("INSERT INTO auth_issuer_access_tokens(realm_id,issuer,id,authorization_id,client_id,user_id,session_id,subject,key_id,access_hash,issued_at_us,expires_at_us,native_refresh,native_family_id,native_generation) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,true,$13,0)")
        .bind(request.authority.realm()).bind(request.authority.issuer()).bind(signed.access_id()).bind(grant.authorization).bind(request.client.client())
        .bind(grant.owner).bind(grant.session).bind(grant.subject).bind(signed.signing().publication().key().id()).bind(signed.access_verifier().as_slice())
        .bind(grant.issued_at_us).bind(signed.expires_at_us()).bind(signed.family_id()).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}
pub(super) async fn created(
    tx: &mut Transaction<'_, Pg>,
    signed: &IssuerNativeSignedCode<'_>,
) -> IssuerTokenResult<()> {
    audit::record(
        tx,
        signed.redemption().authority.realm(),
        AuditEvent::IssuerNativeCredential(IssuerNativeCredentialEvent {
            user_id: signed.grant().owner,
            client_id: signed.redemption().client.client(),
            authorization_id: signed.grant().authorization,
            family_id: signed.family_id(),
            generation: 0,
            action: IssuerNativeCredentialAction::Created,
            credential: IssuerNativeCredentialKind::AuthorizationCode,
        }),
    )
    .await?;
    Ok(())
}
