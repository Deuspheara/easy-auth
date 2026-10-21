use super::configuration;
use crate::{Postgres, deadlines::Deadline, unavailable};
use async_trait::async_trait;
use auth_core::{
    Error, MAX_SAML_PENDING_PER_CONNECTION, Result, SAML_REQUEST_LIFETIME_SECONDS,
    SamlRegistration, SamlRequestAdmission, SamlRequestRepository,
};

#[async_trait]
impl SamlRequestRepository for Postgres {
    async fn save_saml_request(
        &self,
        registration: &SamlRegistration,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<i64> {
        admission.validate()?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Capture the original DB cap before a registry wait can extend admission.
        let cap: i64 = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp()+$1*interval '1 second')*1000000)::bigint",
        )
        .bind(SAML_REQUEST_LIFETIME_SECONDS)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        configuration::lock(&mut tx, registration).await?;
        Deadline::proof(cap).check(&mut tx).await?;
        sqlx::query("DELETE FROM auth_saml_requests WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND expires_at<=clock_timestamp()")
        .bind(registration.realm())
        .bind(registration.connection())
        .bind(registration.client())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_saml_requests WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3")
        .bind(registration.realm())
        .bind(registration.connection())
        .bind(registration.client())
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        if pending >= MAX_SAML_PENDING_PER_CONNECTION {
            return Err(Error::RateLimited);
        }
        sqlx::query(r#"
            INSERT INTO auth_saml_requests(realm_id,connection_id,client_id,revision,request_id,relay_hash,browser_hash,expires_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,to_timestamp($8::double precision/1000000))
        "#)
        .bind(registration.realm())
        .bind(registration.connection())
        .bind(registration.client())
        .bind(registration.revision())
        .bind(admission.request_id)
        .bind(admission.relay.as_slice())
        .bind(admission.browser.as_slice())
        .bind(cap)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        Deadline::proof(cap).check(&mut tx).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(cap / 1000)
    }

    async fn cancel_saml_request(
        &self,
        registration: &SamlRegistration,
        admission: SamlRequestAdmission<'_>,
    ) -> Result<()> {
        super::consumption::take(self, registration, admission).await?;
        Ok(())
    }
}
