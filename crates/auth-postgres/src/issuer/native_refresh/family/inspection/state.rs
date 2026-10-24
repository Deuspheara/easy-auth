use super::super::state::Family;
use crate::{Postgres, unavailable};
use auth_core::{IssuerTokenStatusRequest, Result};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

#[derive(sqlx::FromRow, PartialEq, Eq)]
pub(super) struct Access {
    pub id: Uuid,
    pub authorization_id: Uuid,
    pub client_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub subject: Uuid,
    pub key_id: Uuid,
    pub issued_at_us: i64,
    pub expires_at_us: i64,
    pub revoked_at_us: Option<i64>,
    pub native_family_id: Uuid,
    pub native_generation: i64,
}
const ACCESS_SQL: &str = "SELECT id,authorization_id,client_id,user_id,session_id,subject,key_id,issued_at_us,expires_at_us,revoked_at_us,native_family_id,native_generation FROM auth_issuer_access_tokens WHERE realm_id=$1 AND issuer=$2 AND access_hash=$3 AND native_refresh";
impl Access {
    pub(super) async fn read(
        store: &Postgres,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> Result<Option<Self>> {
        sqlx::query_as(ACCESS_SQL)
            .bind(request.authority.realm())
            .bind(request.authority.issuer())
            .bind(request.token.as_slice())
            .fetch_optional(&store.pool)
            .await
            .map_err(unavailable)
    }
    pub(super) async fn family(
        &self,
        store: &Postgres,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> Result<Option<Family>> {
        sqlx::query_as("SELECT * FROM auth_issuer_native_families WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND id=$4")
            .bind(request.authority.realm()).bind(request.authority.issuer()).bind(self.client_id).bind(self.native_family_id)
            .fetch_optional(&store.pool).await.map_err(unavailable)
    }
    pub(super) async fn lock(
        &self,
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> Result<bool> {
        let locked: Option<Self> = sqlx::query_as(&format!("{ACCESS_SQL} FOR SHARE"))
            .bind(request.authority.realm())
            .bind(request.authority.issuer())
            .bind(request.token.as_slice())
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?;
        Ok(locked.as_ref() == Some(self))
    }
    /// Earlier unexpired access remains inspectable after refresh rotation, but
    /// its exact committed generation history must still exist. Spent refresh
    /// history is not itself a revocation of that generation's access token.
    pub(super) async fn lock_generation(
        &self,
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> Result<bool> {
        let present:Option<bool>=sqlx::query_scalar("SELECT true FROM auth_issuer_native_refresh_tokens WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND family_id=$4 AND authorization_id=$5 AND user_id=$6 AND generation=$7 FOR SHARE")
            .bind(request.authority.realm()).bind(request.authority.issuer()).bind(self.client_id)
            .bind(self.native_family_id).bind(self.authorization_id).bind(self.user_id).bind(self.native_generation)
            .fetch_optional(&mut **tx).await.map_err(unavailable)?;
        Ok(present == Some(true))
    }
    pub(super) fn matches(&self, family: &Family) -> bool {
        self.revoked_at_us.is_none()
            && family.revoked_at_us.is_none()
            && self.native_family_id == family.origin.id
            && self.client_id == family.origin.client_id
            && self.authorization_id == family.origin.authorization_id
            && self.user_id == family.origin.user_id
            && self.session_id == family.origin.session_id
            && self.subject == family.origin.subject
            && self.native_generation <= family.generation
            && self.native_generation >= 0
            && self.issued_at_us >= family.origin.created_at_us
            && self.expires_at_us <= family.origin.expires_at_us
    }
}
