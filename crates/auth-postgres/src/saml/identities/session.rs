use crate::unavailable;
use auth_core::{Result, SamlMappedIdentity, Verifier};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) async fn create(
    tx: &mut Transaction<'_, Postgres>,
    mapped: &SamlMappedIdentity,
    owner: Uuid,
    identity: Uuid,
    bearer: Verifier,
) -> Result<Uuid> {
    let proof = mapped.assertion();
    let reg = proof.registration();
    let id = Uuid::new_v4();
    sqlx::query(r#"
        INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authenticated_at,authentication_method,saml_identity_id,saml_revision)
        VALUES($1,$2,$3,$4,TIMESTAMPTZ 'epoch'+($5::bigint/1000000)*interval '1 second'+($5::bigint%1000000)*interval '1 microsecond','saml',$6,$7)
    "#).bind(reg.realm()).bind(id).bind(owner).bind(bearer.as_slice()).bind(proof.authenticated_at_us()).bind(identity).bind(reg.revision())
        .execute(&mut **tx).await.map_err(unavailable)?;
    // Respect the existing database default absolute policy, then clamp the new
    // private row by the retained signed-session limit in this same transaction.
    sqlx::query("UPDATE auth_sessions SET expires_at=least(expires_at,TIMESTAMPTZ 'epoch'+($3::bigint/1000000)*interval '1 second'+($3::bigint%1000000)*interval '1 microsecond') WHERE realm_id=$1 AND id=$2")
        .bind(reg.realm()).bind(id).bind(proof.session_expires_at_us()).execute(&mut **tx).await.map_err(unavailable)?;
    Ok(id)
}
