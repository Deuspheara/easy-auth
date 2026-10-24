use super::{lock_clients, lock_policy};
use crate::{Postgres, issuer::configuration, unavailable};
use auth_core::{Error, IssuerAuthority, IssuerNativeConsumerPolicy, Result};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct StoredPolicy {
    revision: Uuid,
    consumer_revision: Uuid,
    audience_revision: Uuid,
}
impl Postgres {
    /// Operator provisioning only. Initial rows are disabled; reconfiguration
    /// rotates revision and preserves disable. Both current clients must be enabled.
    pub async fn configure_issuer_native_consumer(
        &self,
        input: &IssuerNativeConsumerPolicy,
    ) -> Result<IssuerNativeConsumerPolicy> {
        let policy = input.reconfigured();
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_clients(
            &mut tx,
            policy.authority().realm(),
            policy.consumer().client(),
            policy.audience().client(),
        )
        .await?;
        configuration::lock(&mut tx, policy.consumer(), true).await?;
        configuration::lock(&mut tx, policy.audience(), true).await?;
        sqlx::query("INSERT INTO auth_issuer_native_consumers(realm_id,issuer,consumer_id,audience_id,revision,consumer_revision,audience_revision) VALUES($1,$2,$3,$4,$5,$6,$7) ON CONFLICT(realm_id,issuer,consumer_id,audience_id) DO UPDATE SET (revision,consumer_revision,audience_revision)=(EXCLUDED.revision,EXCLUDED.consumer_revision,EXCLUDED.audience_revision)")
            .bind(policy.authority().realm()).bind(policy.authority().issuer()).bind(policy.consumer().client())
            .bind(policy.audience().client()).bind(policy.revision()).bind(policy.consumer().revision()).bind(policy.audience().revision())
            .execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(policy)
    }
    pub async fn enable_issuer_native_consumer(
        &self,
        policy: &IssuerNativeConsumerPolicy,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_clients(
            &mut tx,
            policy.authority().realm(),
            policy.consumer().client(),
            policy.audience().client(),
        )
        .await?;
        configuration::lock(&mut tx, policy.consumer(), true).await?;
        configuration::lock(&mut tx, policy.audience(), true).await?;
        lock_policy(&mut tx, policy, false).await?;
        sqlx::query("UPDATE auth_issuer_native_consumers SET enabled=true WHERE realm_id=$1 AND issuer=$2 AND consumer_id=$3 AND audience_id=$4")
            .bind(policy.authority().realm()).bind(policy.authority().issuer()).bind(policy.consumer().client()).bind(policy.audience().client())
            .execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    /// Reduction remains available with stale/disabled client definitions.
    pub async fn disable_issuer_native_consumer(
        &self,
        authority: &IssuerAuthority,
        consumer: Uuid,
        audience: Uuid,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        lock_clients(&mut tx, authority.realm(), consumer, audience).await?;
        sqlx::query("UPDATE auth_issuer_native_consumers SET enabled=false,revision=$5 WHERE realm_id=$1 AND issuer=$2 AND consumer_id=$3 AND audience_id=$4")
            .bind(authority.realm()).bind(authority.issuer()).bind(consumer).bind(audience).bind(Uuid::new_v4())
            .execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    /// Configuration facts only. Active inspection must recheck under its locks.
    pub async fn load_issuer_native_consumer(
        &self,
        authority: &IssuerAuthority,
        consumer: Uuid,
        audience: Uuid,
    ) -> Result<IssuerNativeConsumerPolicy> {
        let reader = self.load_issuer_client(authority.realm(), consumer).await?;
        let native = self.load_issuer_client(authority.realm(), audience).await?;
        let stored:StoredPolicy=sqlx::query_as("SELECT revision,consumer_revision,audience_revision FROM auth_issuer_native_consumers WHERE realm_id=$1 AND issuer=$2 AND consumer_id=$3 AND audience_id=$4 AND enabled")
            .bind(authority.realm()).bind(authority.issuer()).bind(consumer).bind(audience)
            .fetch_optional(&self.pool).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        if stored.consumer_revision != reader.revision()
            || stored.audience_revision != native.revision()
        {
            return Err(Error::Unauthorized);
        }
        IssuerNativeConsumerPolicy::new(authority.clone(), reader, native)
            .and_then(|p| p.with_persisted_revision(stored.revision))
            .map_err(|_| Error::Unavailable)
    }
}
