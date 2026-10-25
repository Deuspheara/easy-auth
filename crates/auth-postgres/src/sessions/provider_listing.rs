use auth_core::{Error, Result};
use sqlx::{Postgres, Row, Transaction, postgres::PgRow};
use uuid::Uuid;

pub(super) async fn list(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    owner: Uuid,
    current: Uuid,
    after: Option<Uuid>,
    limit: i64,
) -> Result<Vec<PgRow>> {
    let mut rows = Vec::new();
    #[cfg(feature = "oidc-identities")]
    rows.extend(super::oidc::list(tx, realm, owner, current, after, limit, false).await?);
    #[cfg(feature = "saml-identities")]
    rows.extend(super::saml::list(tx, realm, owner, current, after, limit).await?);
    // Both queries use the same exact UUID cursor/order. Merge their bounded
    // batches before truncation to preserve one global provider-session page.
    rows.sort_unstable_by_key(|row| row.get::<Uuid, _>("id"));
    rows.truncate(usize::try_from(limit).map_err(|_| Error::InvalidInput)?);
    Ok(rows)
}
