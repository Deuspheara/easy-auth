use crate::{Postgres, sessions::FreshSessionSnapshot, unavailable};
use auth_core::{Error, IssuerTokenStatusRequest, Result, Verifier};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

#[derive(sqlx::FromRow, PartialEq, Eq)]
pub(super) struct AccessState {
    pub id: Uuid,
    pub authorization_id: Uuid,
    pub user_id: Uuid,
    pub session_id: Uuid,
    pub subject: Uuid,
    pub key_id: Uuid,
    pub issued_at_us: i64,
    pub expires_at_us: i64,
    pub revoked_at_us: Option<i64>,
}
pub(super) struct AccessCandidate {
    pub original: AccessState,
    pub owner: FreshSessionSnapshot,
}
const ACCESS_SQL: &str = "SELECT id,authorization_id,user_id,session_id,subject,key_id,issued_at_us,expires_at_us,revoked_at_us FROM auth_issuer_access_tokens WHERE realm_id=$1 AND issuer=$2 AND client_id=$3 AND access_hash=$4";
impl AccessCandidate {
    pub async fn read(
        store: &Postgres,
        request: &IssuerTokenStatusRequest<'_>,
    ) -> Result<Option<Self>> {
        let Some(original) = row(&store.pool, request).await? else {
            return Ok(None);
        };
        let token: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT token_hash FROM auth_sessions WHERE realm_id=$1 AND id=$2 AND user_id=$3",
        )
        .bind(request.authority.realm())
        .bind(original.session_id)
        .bind(original.user_id)
        .fetch_optional(&store.pool)
        .await
        .map_err(unavailable)?;
        let Some(token) = token else { return Ok(None) };
        let current: Verifier = token.try_into().map_err(|_| Error::Unavailable)?;
        let owner =
            match FreshSessionSnapshot::load(&store.pool, request.authority.realm(), current).await
            {
                Ok(owner) => owner,
                Err(Error::Unauthorized) => return Ok(None),
                Err(error) => return Err(error),
            };
        Ok(Some(Self { original, owner }))
    }
}
async fn row(
    pool: &sqlx::PgPool,
    request: &IssuerTokenStatusRequest<'_>,
) -> Result<Option<AccessState>> {
    sqlx::query_as(ACCESS_SQL)
        .bind(request.authority.realm())
        .bind(request.authority.issuer())
        .bind(request.client.client())
        .bind(request.token.as_slice())
        .fetch_optional(pool)
        .await
        .map_err(unavailable)
}
pub(super) async fn locked_row(
    tx: &mut Transaction<'_, Pg>,
    request: &IssuerTokenStatusRequest<'_>,
) -> Result<Option<AccessState>> {
    sqlx::query_as(&format!("{ACCESS_SQL} FOR SHARE"))
        .bind(request.authority.realm())
        .bind(request.authority.issuer())
        .bind(request.client.client())
        .bind(request.token.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)
}
