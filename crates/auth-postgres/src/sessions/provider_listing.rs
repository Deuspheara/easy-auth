use auth_core::Result;
use sqlx::{Postgres, Transaction, postgres::PgRow};
use uuid::Uuid;

pub(super) async fn list(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    owner: Uuid,
    current: Uuid,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<PgRow>> {
    super::oidc::list(tx, realm, owner, current, after, limit).await
}
