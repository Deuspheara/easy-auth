use super::configuration;
use crate::{Postgres, deadlines::Deadline, unavailable};
use auth_core::{Error, Result, SamlRegistration, SamlRequestAdmission, SamlRequestTiming};

/// Consume only the current exact bound request. This creates no identity proof.
pub(super) async fn take(
    store: &Postgres,
    registration: &SamlRegistration,
    admission: SamlRequestAdmission<'_>,
) -> Result<SamlRequestTiming> {
    admission.validate()?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    configuration::lock(&mut tx, registration).await?;
    let row: Option<(i64, i64)> = sqlx::query_as(
        r#"
        DELETE FROM auth_saml_requests
        WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision=$4 AND request_id=$5
          AND relay_hash=$6 AND browser_hash=$7 AND expires_at>clock_timestamp()
        RETURNING (extract(epoch FROM expires_at)*1000000)::bigint,
          (extract(epoch FROM clock_timestamp())*1000000)::bigint
    "#,
    )
    .bind(registration.realm())
    .bind(registration.connection())
    .bind(registration.client())
    .bind(registration.revision())
    .bind(admission.request_id)
    .bind(admission.relay.as_slice())
    .bind(admission.browser.as_slice())
    .fetch_optional(&mut *tx)
    .await
    .map_err(unavailable)?;
    let (cap, observed_at_us) = row.ok_or(Error::Unauthorized)?;
    Deadline::proof(cap).check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(SamlRequestTiming {
        expires_at_us: cap,
        observed_at_us,
    })
}
