use crate::{Postgres, unavailable};
use auth_core::{Error, IssuerNativeCredentialRequest, IssuerNativeRefreshPolicy, Result};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

#[derive(sqlx::FromRow, PartialEq, Eq)]
pub(super) struct Origin {
    pub realm_id: Uuid,
    pub issuer: String,
    pub id: Uuid,
    pub authorization_id: Uuid,
    pub client_id: Uuid,
    pub client_revision: Uuid,
    pub policy_revision: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub subject: Uuid,
    pub authentication_method: String,
    pub authenticated_at_us: i64,
    pub lifetime_seconds: i32,
    pub idle_seconds: i32,
    pub prepared_at_us: i64,
    pub approved_at_us: i64,
    pub source_absolute_cap_us: i64,
    pub created_at_us: i64,
    pub expires_at_us: i64,
}
#[derive(sqlx::FromRow)]
pub(super) struct Family {
    #[sqlx(flatten)]
    pub origin: Origin,
    pub idle_until_us: i64,
    pub generation: i64,
    pub revoked_at_us: Option<i64>,
}
#[derive(sqlx::FromRow)]
pub(super) struct Refresh {
    pub generation: i64,
    pub spent_at_us: Option<i64>,
}
impl Family {
    pub(super) async fn refresh(
        store: &Postgres,
        request: &IssuerNativeCredentialRequest<'_>,
    ) -> Result<Option<Self>> {
        sqlx::query_as("SELECT f.* FROM auth_issuer_native_families f JOIN auth_issuer_native_refresh_tokens t ON (t.realm_id,t.family_id)=(f.realm_id,f.id) WHERE f.realm_id=$1 AND f.issuer=$2 AND f.client_id=$3 AND t.issuer=$2 AND t.client_id=$3 AND t.token_hash=$4")
            .bind(request.authority.realm()).bind(request.authority.issuer()).bind(request.client.client()).bind(request.token.as_slice())
            .fetch_optional(&store.pool).await.map_err(unavailable)
    }
    pub(super) async fn access(
        store: &Postgres,
        request: &IssuerNativeCredentialRequest<'_>,
    ) -> Result<Option<(Self, i64)>> {
        let row:Option<(Uuid,i64)>=sqlx::query_as("SELECT native_family_id,native_generation FROM auth_issuer_access_tokens WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND access_hash=$4 AND native_refresh")
            .bind(request.authority.realm()).bind(request.authority.issuer()).bind(request.client.client()).bind(request.token.as_slice()).fetch_optional(&store.pool).await.map_err(unavailable)?;
        let Some((id, generation)) = row else {
            return Ok(None);
        };
        let family:Option<Self>=sqlx::query_as("SELECT * FROM auth_issuer_native_families WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND id=$4")
            .bind(request.authority.realm()).bind(request.authority.issuer()).bind(request.client.client()).bind(id).fetch_optional(&store.pool).await.map_err(unavailable)?;
        Ok(family.map(|f| (f, generation)))
    }
    pub(super) async fn lock(&self, tx: &mut Transaction<'_, Pg>) -> Result<Option<Self>> {
        let locked:Option<Self>=sqlx::query_as("SELECT * FROM auth_issuer_native_families WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND id=$4 FOR UPDATE")
            .bind(self.origin.realm_id).bind(&self.origin.issuer).bind(self.origin.client_id).bind(self.origin.id).fetch_optional(&mut **tx).await.map_err(unavailable)?;
        if locked.as_ref().is_some_and(|f| f.origin != self.origin) {
            return Err(Error::Unauthorized);
        }
        Ok(locked)
    }
    pub(super) fn policy(
        &self,
        request: &IssuerNativeCredentialRequest<'_>,
    ) -> Result<IssuerNativeRefreshPolicy> {
        if self.origin.client_revision != request.client.revision()
            || self.origin.realm_id != request.authority.realm()
            || self.origin.issuer != request.authority.issuer()
            || self.origin.client_id != request.client.client()
        {
            return Err(Error::Unauthorized);
        }
        IssuerNativeRefreshPolicy::new(
            request.authority.clone(),
            request.client.clone(),
            self.origin
                .lifetime_seconds
                .try_into()
                .map_err(|_| Error::Unavailable)?,
            self.origin
                .idle_seconds
                .try_into()
                .map_err(|_| Error::Unavailable)?,
        )?
        .with_persisted_revision(self.origin.policy_revision)
    }
}
impl Refresh {
    pub(super) async fn read(
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerNativeCredentialRequest<'_>,
        family: Uuid,
    ) -> Result<Option<Self>> {
        sqlx::query_as("SELECT generation,spent_at_us FROM auth_issuer_native_refresh_tokens WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND family_id=$4 AND token_hash=$5")
            .bind(request.authority.realm()).bind(request.authority.issuer()).bind(request.client.client()).bind(family).bind(request.token.as_slice()).fetch_optional(&mut **tx).await.map_err(unavailable)
    }
    pub(super) async fn lock(
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerNativeCredentialRequest<'_>,
        family: Uuid,
    ) -> Result<Option<Self>> {
        sqlx::query_as("SELECT generation,spent_at_us FROM auth_issuer_native_refresh_tokens WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND family_id=$4 AND token_hash=$5 FOR UPDATE")
            .bind(request.authority.realm()).bind(request.authority.issuer()).bind(request.client.client()).bind(family).bind(request.token.as_slice()).fetch_optional(&mut **tx).await.map_err(unavailable)
    }
}
