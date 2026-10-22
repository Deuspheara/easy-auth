use super::authorization;
use crate::{Postgres, deadlines::Deadline, saml::identity_policy, unavailable};
use auth_core::{
    Error, Result, SamlDeletionRequestContext, SamlRegistration, SamlRequestAdmission,
    SamlRequestTiming, Verifier,
};

pub(super) async fn take(
    store: &Postgres,
    reg: &SamlRegistration,
    current: Verifier,
    admission: SamlRequestAdmission<'_>,
) -> Result<SamlDeletionRequestContext> {
    admission.validate()?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    identity_policy::load(&mut tx, reg).await?;
    let owner = authorization::lock(&mut tx, reg, current).await?;
    let b = &owner.binding;
    let row: Option<(i64, i64)> = sqlx::query_as(r#"
        DELETE FROM auth_saml_requests
        WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision=$4 AND request_id=$5
          AND relay_hash=$6 AND browser_hash=$7 AND purpose='delete_account'
          AND user_id=$8 AND session_id=$9 AND identity_id=$10 AND expires_at>clock_timestamp()
        RETURNING (extract(epoch FROM expires_at)*1000000)::bigint,(extract(epoch FROM clock_timestamp())*1000000)::bigint
    "#)
    .bind(reg.realm())
    .bind(reg.connection())
    .bind(reg.client())
    .bind(reg.revision())
    .bind(admission.request_id)
    .bind(admission.relay.as_slice())
    .bind(admission.browser.as_slice())
    .bind(b.user)
    .bind(b.session)
    .bind(b.identity)
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    let (cap, observed_at_us) = row.ok_or(Error::Unauthorized)?;
    let deadline = owner.deadline.with_proof(cap);
    deadline.check(&mut tx).await?;
    Deadline::proof(cap).check(&mut tx).await?;
    // The earliest parent/request cap remains the final statement before commit.
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(SamlDeletionRequestContext {
        binding: owner.binding,
        timing: SamlRequestTiming {
            expires_at_us: cap,
            observed_at_us,
        },
    })
}
