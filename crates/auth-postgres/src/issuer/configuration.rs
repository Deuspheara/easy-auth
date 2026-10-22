use crate::{Postgres, unavailable};
use auth_core::{Error, IssuerClientKind, IssuerClientRegistration, Result};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

fn authentication(client: &IssuerClientRegistration) -> &'static str {
    match client.kind() {
        IssuerClientKind::Public => "none",
        IssuerClientKind::ConfidentialBasic => "client_secret_basic",
    }
}
impl Postgres {
    /// Trusted administrative provisioning, not dynamic browser registration.
    /// A stale input cannot preserve its revision or implicitly clear disable.
    pub async fn configure_issuer_client(
        &self,
        input: &IssuerClientRegistration,
    ) -> Result<IssuerClientRegistration> {
        let client = input.reconfigured();
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query(
            "INSERT INTO auth_issuer_sectors(realm_id,host) VALUES ($1,$2) ON CONFLICT DO NOTHING",
        )
        .bind(client.realm())
        .bind(client.sector())
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?;
        sqlx::query(
            r#"
            INSERT INTO auth_issuer_clients(realm_id,id,revision,sector,redirect_uris,authentication,secret_verifier)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            ON CONFLICT (realm_id,id) DO UPDATE SET
                (revision,sector,redirect_uris,authentication,secret_verifier) =
                (EXCLUDED.revision,EXCLUDED.sector,EXCLUDED.redirect_uris,
                 EXCLUDED.authentication,EXCLUDED.secret_verifier)
            "#,
        ).bind(client.realm()).bind(client.client()).bind(client.revision())
            .bind(client.sector()).bind(client.redirects()).bind(authentication(&client))
            .bind(client.secret_verifier().map(|v| v.to_vec()))
            .execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(client)
    }
    pub async fn disable_issuer_client(&self, realm: Uuid, client: Uuid) -> Result<()> {
        sqlx::query(
            "UPDATE auth_issuer_clients SET enabled=false,revision=$3 WHERE realm_id=$1 AND id=$2",
        )
        .bind(realm)
        .bind(client)
        .bind(Uuid::new_v4())
        .execute(&self.pool)
        .await
        .map_err(unavailable)?;
        Ok(())
    }
    /// Enable only the current full definition. Old revisions never regain validity.
    pub async fn enable_issuer_client(&self, client: &IssuerClientRegistration) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock(&mut tx, client, false).await?;
        sqlx::query("UPDATE auth_issuer_clients SET enabled=true WHERE realm_id=$1 AND id=$2")
            .bind(client.realm())
            .bind(client.client())
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    /// Check trusted metadata only. This does not authenticate any client or user.
    pub async fn check_issuer_client(&self, client: &IssuerClientRegistration) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock(&mut tx, client, true).await?;
        tx.commit().await.map_err(unavailable)
    }
}

/// Client-before-owner ordering. Full definition equality catches stale or altered
/// storage as well as revisions; no request field may supply this trusted snapshot.
pub(super) async fn lock(
    tx: &mut Transaction<'_, Pg>,
    client: &IssuerClientRegistration,
    require_enabled: bool,
) -> Result<()> {
    let enabled: Option<bool> = sqlx::query_scalar(
        r#"
        SELECT enabled FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2 AND revision=$3
            AND sector=$4 AND redirect_uris=$5 AND authentication=$6
            AND secret_verifier IS NOT DISTINCT FROM $7
            AND consent='explicit' AND subject_type='pairwise' FOR UPDATE
        "#,
    )
    .bind(client.realm())
    .bind(client.client())
    .bind(client.revision())
    .bind(client.sector())
    .bind(client.redirects())
    .bind(authentication(client))
    .bind(client.secret_verifier().map(|v| v.to_vec()))
    .fetch_optional(&mut **tx)
    .await
    .map_err(unavailable)?;
    if enabled.is_none() || (require_enabled && enabled != Some(true)) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}
