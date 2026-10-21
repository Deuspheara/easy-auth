use crate::{Postgres, unavailable};
use auth_core::{Error, Result, SamlRegistration};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

impl Postgres {
    /// Trusted administration only. Reconfiguration allocates a fresh revision,
    /// retains disable and cancels old pending state in the same transaction.
    pub async fn configure_saml_registration(
        &self,
        input: &SamlRegistration,
    ) -> Result<SamlRegistration> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let registration = replace_registration(&mut tx, input).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(registration)
    }

    pub async fn disable_saml_registration(
        &self,
        realm: Uuid,
        connection: Uuid,
        client: Uuid,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let updated = sqlx::query("UPDATE auth_saml_registrations SET enabled=false,revision=$4 WHERE realm_id=$1 AND id=$2 AND client_id=$3")
        .bind(realm)
        .bind(connection)
        .bind(client)
        .bind(Uuid::new_v4())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?.rows_affected();
        if updated != 1 {
            return Err(Error::Unauthorized);
        }
        clear_requests(&mut tx, realm, connection, client).await?;
        tx.commit().await.map_err(unavailable)
    }

    /// Explicitly re-enable the latest configured revision. Configuration itself
    /// never re-enables an existing disabled registration.
    pub async fn enable_saml_registration(&self, registration: &SamlRegistration) -> Result<()> {
        let updated = sqlx::query("UPDATE auth_saml_registrations SET enabled=true WHERE realm_id=$1 AND id=$2 AND client_id=$3 AND revision=$4")
        .bind(registration.realm())
        .bind(registration.connection())
        .bind(registration.client())
        .bind(registration.revision())
        .execute(&self.pool)
        .await
        .map_err(unavailable)?.rows_affected();
        if updated != 1 {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

async fn clear_requests(
    tx: &mut Transaction<'_, Pg>,
    realm: Uuid,
    connection: Uuid,
    client: Uuid,
) -> Result<()> {
    sqlx::query(
        "DELETE FROM auth_saml_requests WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3",
    )
    .bind(realm)
    .bind(connection)
    .bind(client)
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    Ok(())
}

/// Serialize admission/cancellation/configuration per exact registry key before
/// taking request locks. No lock spans XML generation, network or cryptography.
pub(super) async fn lock(
    tx: &mut Transaction<'_, Pg>,
    registration: &SamlRegistration,
) -> Result<()> {
    let enabled: Option<bool> = sqlx::query_scalar(r#"
        SELECT enabled FROM auth_saml_registrations WHERE realm_id=$1 AND id=$2 AND client_id=$3
          AND revision=$4 AND sp_entity=$5 AND idp_entity=$6 AND sso_url=$7 AND acs_url=$8 FOR UPDATE
    "#)
        .bind(registration.realm())
        .bind(registration.connection())
        .bind(registration.client())
        .bind(registration.revision())
        .bind(registration.sp_entity())
        .bind(registration.idp_entity())
        .bind(registration.sso())
        .bind(registration.acs())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
    if enabled != Some(true) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

pub(super) async fn replace_registration(
    tx: &mut Transaction<'_, Pg>,
    input: &SamlRegistration,
) -> Result<SamlRegistration> {
    let registration = input.reconfigured();
    sqlx::query(r#"
        INSERT INTO auth_saml_registrations(realm_id,id,client_id,revision,sp_entity,idp_entity,sso_url,acs_url)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
        ON CONFLICT (realm_id,id,client_id) DO UPDATE SET
          revision=EXCLUDED.revision,sp_entity=EXCLUDED.sp_entity,idp_entity=EXCLUDED.idp_entity,
          sso_url=EXCLUDED.sso_url,acs_url=EXCLUDED.acs_url
    "#)
    .bind(registration.realm())
    .bind(registration.connection())
    .bind(registration.client())
    .bind(registration.revision())
    .bind(registration.sp_entity())
    .bind(registration.idp_entity())
    .bind(registration.sso())
    .bind(registration.acs())
    .execute(&mut **tx)
    .await
    .map_err(unavailable)?;
    clear_requests(
        tx,
        registration.realm(),
        registration.connection(),
        registration.client(),
    )
    .await?;
    Ok(registration)
}
