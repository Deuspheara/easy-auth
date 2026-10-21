use super::deleted;
use crate::{
    identity::{lock_provider_user, user_from_row},
    unavailable,
};
use auth_core::{Error, Result, SamlJitPolicy, SamlMappedIdentity, User};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn resolve(
    tx: &mut Transaction<'_, Postgres>,
    mapped: &SamlMappedIdentity,
) -> Result<(User, Uuid)> {
    let proof = mapped.assertion();
    let reg = proof.registration();
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode(auth_saml_subject_key($1,$2,$3,$4,$5,$6),'hex'),0))")
        .bind(reg.realm()).bind(reg.connection()).bind(reg.client()).bind(reg.idp_entity()).bind(reg.sp_entity()).bind(proof.subject())
        .execute(&mut **tx).await.map_err(unavailable)?;
    let existing: Option<(Uuid,Uuid,Option<String>)> = sqlx::query_as(r#"
        SELECT e.id,e.user_id,u.email FROM auth_saml_identities e JOIN auth_users u ON u.realm_id=e.realm_id AND u.id=e.user_id
        WHERE e.realm_id=$1 AND e.subject_hash=auth_saml_subject_key($1,$2,$3,$4,$5,$6) AND e.connection_id=$2 AND e.client_id=$3 AND e.idp_entity=$4 AND e.sp_entity=$5 AND e.subject=$6
    "#).bind(reg.realm()).bind(reg.connection()).bind(reg.client()).bind(reg.idp_entity()).bind(reg.sp_entity()).bind(proof.subject())
        .fetch_optional(&mut **tx).await.map_err(unavailable)?;
    if let Some((identity, owner, email)) = existing {
        let user = lock_provider_user(tx, reg.realm(), owner, email.as_deref()).await?;
        let bound: Option<Uuid> = sqlx::query_scalar(r#"
            SELECT id FROM auth_saml_identities WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND connection_id=$4
              AND client_id=$5 AND idp_entity=$6 AND sp_entity=$7 AND subject=$8 FOR UPDATE
        "#).bind(reg.realm()).bind(identity).bind(owner).bind(reg.connection()).bind(reg.client())
            .bind(reg.idp_entity()).bind(reg.sp_entity()).bind(proof.subject())
            .fetch_optional(&mut **tx).await.map_err(unavailable)?;
        if bound != Some(identity) {
            return Err(Error::Unauthorized);
        }
        // A vanished/changed owner never falls through to new-owner JIT.
        return Ok((user, identity));
    }
    create(tx, mapped).await
}

async fn create(
    tx: &mut Transaction<'_, Postgres>,
    mapped: &SamlMappedIdentity,
) -> Result<(User, Uuid)> {
    if mapped.policy().jit() != SamlJitPolicy::Allow {
        return Err(Error::Unauthorized);
    }
    let display_name = mapped.display_name().ok_or(Error::Unauthorized)?;
    deleted::reject(tx, mapped).await?;
    let reg = mapped.assertion().registration();
    let owner = Uuid::new_v4();
    let row = sqlx::query("INSERT INTO auth_users(realm_id,id,email,email_verified_at,display_name,authentication_policy) VALUES($1,$2,NULL,NULL,$3,'provider_required') RETURNING id,email,display_name,authentication_policy")
        .bind(reg.realm()).bind(owner).bind(display_name).fetch_one(&mut **tx).await.map_err(unavailable)?;
    let identity = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_saml_identities(realm_id,id,connection_id,client_id,idp_entity,sp_entity,subject,user_id,subject_hash) VALUES($1,$2,$3,$4,$5,$6,$7,$8,auth_saml_subject_key($1,$3,$4,$5,$6,$7))")
        .bind(reg.realm()).bind(identity).bind(reg.connection()).bind(reg.client()).bind(reg.idp_entity()).bind(reg.sp_entity())
        .bind(mapped.assertion().subject()).bind(owner).execute(&mut **tx).await.map_err(unavailable)?;
    Ok((user_from_row(reg.realm(), &row)?, identity))
}
