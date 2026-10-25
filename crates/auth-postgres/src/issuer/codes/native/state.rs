use super::super::state::AuthorizationState;
use crate::{Postgres, unavailable};
use auth_core::{
    Error, IssuerAuthority, IssuerClientRegistration, IssuerNativeConsentData,
    IssuerNativeRefreshPolicy, Result,
};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

#[derive(sqlx::FromRow, PartialEq, Eq)]
pub(in crate::issuer::codes) struct ConsentState {
    realm_id: Uuid,
    authorization_id: Uuid,
    issuer: String,
    client_id: Uuid,
    client_revision: Uuid,
    user_id: Uuid,
    session_id: Uuid,
    native_refresh: bool,
    policy_revision: Uuid,
    lifetime_seconds: i32,
    idle_seconds: i32,
    prepared_at_us: i64,
    source_absolute_cap_us: i64,
    pub(super) grant_expires_at_us: i64,
    approved_at_us: Option<i64>,
}
impl ConsentState {
    pub(super) async fn load(store: &Postgres, state: &AuthorizationState) -> Result<Self> {
        sqlx::query_as(
            "SELECT * FROM auth_issuer_native_consents WHERE realm_id=$1 AND authorization_id=$2",
        )
        .bind(state.realm_id)
        .bind(state.id)
        .fetch_optional(&store.pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)
    }
    pub(super) async fn lock(
        &self,
        tx: &mut Transaction<'_, Pg>,
        state: &AuthorizationState,
    ) -> Result<()> {
        self.lock_snapshot(tx, state).await?;
        if self.approved_at_us.is_some() {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    pub(super) async fn lock_approved(
        &self,
        tx: &mut Transaction<'_, Pg>,
        state: &AuthorizationState,
    ) -> Result<()> {
        self.lock_snapshot(tx, state).await?;
        if self.approved_at_us.is_none()
            || self.approved_at_us != state.approved_at_us
            || state.status != "approved"
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    async fn lock_snapshot(
        &self,
        tx: &mut Transaction<'_, Pg>,
        state: &AuthorizationState,
    ) -> Result<()> {
        let locked: Self = sqlx::query_as("SELECT * FROM auth_issuer_native_consents WHERE realm_id=$1 AND authorization_id=$2 FOR UPDATE")
            .bind(state.realm_id).bind(state.id).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        if &locked != self
            || self.realm_id != state.realm_id
            || self.authorization_id != state.id
            || self.issuer != state.issuer
            || self.client_id != state.client_id
            || self.client_revision != state.client_revision
            || self.user_id != state.user_id
            || self.session_id != state.session_id
            || !self.native_refresh
            || !state.native_refresh
            || self.prepared_at_us != state.created_at_us
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    pub(super) fn data(
        &self,
        authority: &IssuerAuthority,
        client: &IssuerClientRegistration,
    ) -> Result<IssuerNativeConsentData> {
        let policy = IssuerNativeRefreshPolicy::new(
            authority.clone(),
            client.clone(),
            self.lifetime_seconds
                .try_into()
                .map_err(|_| Error::Unavailable)?,
            self.idle_seconds
                .try_into()
                .map_err(|_| Error::Unavailable)?,
        )?
        .with_persisted_revision(self.policy_revision)?;
        if policy.grant_expires_at_us(self.prepared_at_us, self.source_absolute_cap_us)?
            != self.grant_expires_at_us
        {
            return Err(Error::Unavailable);
        }
        Ok(IssuerNativeConsentData {
            policy,
            prepared_at_us: self.prepared_at_us,
            source_absolute_cap_us: self.source_absolute_cap_us,
            grant_expires_at_us: self.grant_expires_at_us,
            approved_at_us: self.approved_at_us,
        })
    }
    pub(super) async fn approve(&self, tx: &mut Transaction<'_, Pg>, at: i64) -> Result<()> {
        let changed=sqlx::query("UPDATE auth_issuer_native_consents SET approved_at_us=$3 WHERE realm_id=$1 AND authorization_id=$2 AND approved_at_us IS NULL")
            .bind(self.realm_id).bind(self.authorization_id).bind(at).execute(&mut **tx).await.map_err(unavailable)?.rows_affected();
        if changed != 1 {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

impl ConsentState {
    pub(super) async fn snapshot(&self, tx: &mut Transaction<'_, Pg>) -> Result<String> {
        sqlx::query_scalar("SELECT to_jsonb(c)::text FROM auth_issuer_native_consents c WHERE realm_id=$1 AND authorization_id=$2")
            .bind(self.realm_id).bind(self.authorization_id).fetch_one(&mut **tx).await.map_err(unavailable)
    }
}
