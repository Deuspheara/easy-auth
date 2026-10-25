use super::policy;
use crate::{Postgres, unavailable};
use auth_core::{Error, IssuerAuthority, IssuerNativeRefreshPolicy, Result};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct StoredPolicy {
    revision: Uuid,
    client_revision: Uuid,
    lifetime_seconds: i32,
    idle_seconds: i32,
}

impl Postgres {
    /// Trusted provisioning only. New rows are disabled; replacing a disabled
    /// policy cannot enable it. Current client configuration must already be enabled.
    pub async fn configure_issuer_native_refresh_policy(
        &self,
        input: &IssuerNativeRefreshPolicy,
    ) -> Result<IssuerNativeRefreshPolicy> {
        let policy = input.reconfigured();
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        super::super::configuration::lock(&mut tx, policy.client(), true).await?;
        sqlx::query(
            "INSERT INTO auth_issuer_native_refresh_policies(realm_id,issuer,client_id,revision,client_revision,lifetime_seconds,idle_seconds) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (realm_id,issuer,client_id) DO UPDATE SET (revision,client_revision,lifetime_seconds,idle_seconds)=(EXCLUDED.revision,EXCLUDED.client_revision,EXCLUDED.lifetime_seconds,EXCLUDED.idle_seconds)",
        ).bind(policy.authority().realm()).bind(policy.authority().issuer())
            .bind(policy.client().client()).bind(policy.revision()).bind(policy.client().revision())
            .bind(i64::from(policy.lifetime_seconds())).bind(i64::from(policy.idle_seconds()))
            .execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(policy)
    }
    /// Enable only the current full policy and current enabled client definition.
    pub async fn enable_issuer_native_refresh_policy(
        &self,
        input: &IssuerNativeRefreshPolicy,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        super::super::configuration::lock(&mut tx, input.client(), true).await?;
        policy::lock(&mut tx, input, false).await?;
        sqlx::query("UPDATE auth_issuer_native_refresh_policies SET enabled=true WHERE realm_id=$1 AND issuer=$2 AND client_id=$3")
            .bind(input.authority().realm()).bind(input.authority().issuer()).bind(input.client().client())
            .execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    /// Reduces authority even when the client is disabled or its policy is stale.
    pub async fn disable_issuer_native_refresh_policy(
        &self,
        authority: &IssuerAuthority,
        client: Uuid,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("SELECT id FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2 FOR UPDATE")
            .bind(authority.realm())
            .bind(client)
            .fetch_optional(&mut *tx)
            .await
            .map_err(unavailable)?;
        sqlx::query("UPDATE auth_issuer_native_refresh_policies SET enabled=false,revision=$4 WHERE realm_id=$1 AND issuer=$2 AND client_id=$3")
            .bind(authority.realm()).bind(authority.issuer()).bind(client).bind(Uuid::new_v4())
            .execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    /// Point-in-time configuration facts only. This performs no write or enable.
    pub async fn load_issuer_native_refresh_policy(
        &self,
        authority: &IssuerAuthority,
        client: Uuid,
    ) -> Result<IssuerNativeRefreshPolicy> {
        let registration = self.load_issuer_client(authority.realm(), client).await?;
        let stored: StoredPolicy = sqlx::query_as("SELECT revision,client_revision,lifetime_seconds,idle_seconds FROM auth_issuer_native_refresh_policies WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND enabled")
            .bind(authority.realm()).bind(authority.issuer()).bind(client).fetch_optional(&self.pool)
            .await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        if stored.client_revision != registration.revision() {
            return Err(Error::Unauthorized);
        }
        IssuerNativeRefreshPolicy::new(
            authority.clone(),
            registration,
            stored
                .lifetime_seconds
                .try_into()
                .map_err(|_| Error::Unavailable)?,
            stored
                .idle_seconds
                .try_into()
                .map_err(|_| Error::Unavailable)?,
        )
        .and_then(|policy| policy.with_persisted_revision(stored.revision))
        .map_err(|_| Error::Unavailable)
    }
    /// Full locked current-definition check, not consent or authentication.
    pub async fn check_issuer_native_refresh_policy(
        &self,
        input: &IssuerNativeRefreshPolicy,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        super::super::configuration::lock(&mut tx, input.client(), true).await?;
        policy::lock(&mut tx, input, true).await?;
        tx.commit().await.map_err(unavailable)
    }
}
