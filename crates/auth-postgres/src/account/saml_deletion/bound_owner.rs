use super::authorization::{self, Owner};
use crate::unavailable;
use auth_core::{Error, Result, SamlDeletionBinding, SamlRegistration, Verifier};
use sqlx::{Postgres, Transaction};

/// Caller holds full source/policy. The binding comes only from consumed private
/// request proofs plus the concrete signature verifier, never browser UUID input.
pub(super) async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    reg: &SamlRegistration,
    binding: &SamlDeletionBinding,
) -> Result<Owner> {
    // Resolve only this initiating session's irreversible stored verifier. Reuse
    // every current-bearer/source/owner/session/identity check under the usual
    // locks; this lookup itself supplies no authority or raw bearer secret.
    let hash: Vec<u8> = sqlx::query_scalar(
        r#"
        SELECT token_hash FROM auth_sessions
        WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND saml_identity_id=$4
          AND authentication_method='saml' AND saml_revision=$5
    "#,
    )
    .bind(reg.realm())
    .bind(binding.session)
    .bind(binding.user)
    .bind(binding.identity)
    .bind(reg.revision())
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?
    .ok_or(Error::Unauthorized)?;
    let current: Verifier = hash.try_into().map_err(|_| Error::Unavailable)?;
    let owner = authorization::lock(tx, reg, current).await?;
    if owner.binding.user != binding.user
        || owner.binding.session != binding.session
        || owner.binding.identity != binding.identity
    {
        return Err(Error::Unauthorized);
    }
    Ok(owner)
}
