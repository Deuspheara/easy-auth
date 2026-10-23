use crate::unavailable;
use auth_core::{Error, IssuerAuthority, IssuerKeyPublication, IssuerPublicKey, Result};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
pub(super) struct KeyRow {
    pub id: Uuid,
    pub public_jwk: serde_json::Value,
    pub sign_from_us: i64,
    pub sign_until_us: i64,
    pub verify_until_us: i64,
    pub ready_at_us: i64,
    pub enabled: bool,
}
impl KeyRow {
    pub(super) fn publication(&self, authority: &IssuerAuthority) -> Result<IssuerKeyPublication> {
        let bytes = serde_json::to_vec(&self.public_jwk).map_err(|_| Error::Unavailable)?;
        let key = IssuerPublicKey::from_json(&bytes).map_err(|_| Error::Unavailable)?;
        if key.id() != self.id {
            return Err(Error::Unavailable);
        }
        IssuerKeyPublication::new(
            authority.clone(),
            key,
            self.sign_from_us,
            self.sign_until_us,
            self.verify_until_us,
        )
        .map_err(|_| Error::Unavailable)
    }
}
pub(super) async fn now(tx: &mut Transaction<'_, Postgres>) -> Result<i64> {
    sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
        .fetch_one(&mut **tx)
        .await
        .map_err(unavailable)
}
pub(super) async fn lock_namespace(
    tx: &mut Transaction<'_, Postgres>,
    authority: &IssuerAuthority,
) -> Result<(bool, bool, Option<Uuid>)> {
    sqlx::query_as("SELECT enabled,bootstrapped,active_key FROM auth_issuer_key_sets WHERE realm_id=$1 AND issuer=$2 FOR UPDATE")
        .bind(authority.realm()).bind(authority.issuer()).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)
}
pub(super) async fn revise(
    tx: &mut Transaction<'_, Postgres>,
    authority: &IssuerAuthority,
) -> Result<Uuid> {
    let revision = Uuid::new_v4();
    sqlx::query("UPDATE auth_issuer_key_sets SET revision=$3 WHERE realm_id=$1 AND issuer=$2")
        .bind(authority.realm())
        .bind(authority.issuer())
        .bind(revision)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
    Ok(revision)
}
