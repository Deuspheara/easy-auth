use crate::{deadlines::Deadline, identity::lock_provider_user, unavailable};
use auth_core::{Error, Result, SamlDeletionBinding, SamlRegistration, Verifier};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) struct Owner {
    pub binding: SamlDeletionBinding,
    pub deadline: Deadline,
}
/// Caller holds exact configuration/policy first. Do not select another source
/// from browser input or reverse the existing email -> owner -> session order.
pub(super) async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    reg: &SamlRegistration,
    current: Verifier,
) -> Result<Owner> {
    let (user, identity, email): (Uuid, Uuid, Option<String>) = sqlx::query_as(r#"
        SELECT s.user_id,e.id,u.email FROM auth_sessions s
        JOIN auth_users u ON u.realm_id=s.realm_id AND u.id=s.user_id
        JOIN auth_saml_identities e ON e.realm_id=s.realm_id AND e.id=s.saml_identity_id AND e.user_id=s.user_id
        WHERE s.realm_id=$1 AND s.token_hash=$2 AND s.authentication_method='saml' AND s.saml_revision=$3
          AND e.connection_id=$4 AND e.client_id=$5 AND e.idp_entity=$6 AND e.sp_entity=$7
    "#)
    .bind(reg.realm())
    .bind(current.as_slice())
    .bind(reg.revision())
    .bind(reg.connection())
    .bind(reg.client())
    .bind(reg.idp_entity())
    .bind(reg.sp_entity())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    lock_provider_user(tx, reg.realm(), user, email.as_deref()).await?;
    let session: Uuid = sqlx::query_scalar(r#"
        SELECT id FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND token_hash=$3
          AND authentication_method='saml' AND saml_identity_id=$4 AND saml_revision=$5
          AND revoked_at IS NULL AND expires_at>clock_timestamp() AND last_seen_at>clock_timestamp()-interval '30 minutes'
        FOR UPDATE
    "#)
    .bind(reg.realm())
    .bind(user)
    .bind(current.as_slice())
    .bind(identity)
    .bind(reg.revision())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let bound: Option<Uuid> = sqlx::query_scalar(
        r#"
        SELECT id FROM auth_saml_identities WHERE realm_id=$1 AND id=$2 AND user_id=$3
          AND connection_id=$4 AND client_id=$5 AND idp_entity=$6 AND sp_entity=$7 FOR UPDATE
    "#,
    )
    .bind(reg.realm())
    .bind(identity)
    .bind(user)
    .bind(reg.connection())
    .bind(reg.client())
    .bind(reg.idp_entity())
    .bind(reg.sp_entity())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?;
    if bound != Some(identity) {
        return Err(Error::Unauthorized);
    }
    let deadline = Deadline::active_session(tx, reg.realm(), user, session).await?;
    deadline.check(tx).await?;
    Ok(Owner {
        binding: SamlDeletionBinding {
            user,
            session,
            identity,
        },
        deadline,
    })
}
