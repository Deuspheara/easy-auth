use super::state::KeyRow;
use crate::{Postgres, unavailable};
use auth_core::{
    Error, IssuerAuthority, IssuerPublicKey, IssuerSigningSnapshot, MAX_ISSUER_PUBLISHED_KEYS,
    Result,
};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct ActiveKeyRow {
    revision: Uuid,
    #[sqlx(flatten)]
    key: KeyRow,
}

const CURRENT_KEY_SQL: &str = r#"
            SELECT s.revision,k.id,k.public_jwk,k.sign_from_us,k.sign_until_us,k.verify_until_us,k.ready_at_us,k.enabled
            FROM auth_issuer_key_sets s JOIN auth_issuer_keys k
              ON k.realm_id=s.realm_id AND k.issuer=s.issuer AND k.id=s.active_key
            WHERE s.realm_id=$1 AND s.issuer=$2 AND s.enabled AND k.enabled
              AND k.ready_at_us<=(extract(epoch FROM clock_timestamp())*1000000)::bigint
              AND k.sign_from_us<=(extract(epoch FROM clock_timestamp())*1000000)::bigint
              AND k.sign_until_us>(extract(epoch FROM clock_timestamp())*1000000)::bigint
        "#;
impl ActiveKeyRow {
    fn snapshot(self, authority: &IssuerAuthority) -> Result<IssuerSigningSnapshot> {
        IssuerSigningSnapshot::from_persisted(self.revision, self.key.publication(authority)?)
            .map_err(|_| Error::Unavailable)
    }
}
pub(in crate::issuer) async fn lock_current(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    authority: &IssuerAuthority,
) -> Result<IssuerSigningSnapshot> {
    let query = format!("{CURRENT_KEY_SQL} FOR SHARE OF s,k");
    let row: ActiveKeyRow = sqlx::query_as(&query)
        .bind(authority.realm())
        .bind(authority.issuer())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unavailable)?;
    row.snapshot(authority)
}

impl Postgres {
    /// Current metadata only. Issuance must retain/recheck it in its own final
    /// transaction; this read neither freezes a key nor creates token authority.
    pub async fn load_issuer_signing(
        &self,
        authority: &IssuerAuthority,
    ) -> Result<IssuerSigningSnapshot> {
        let row: ActiveKeyRow = sqlx::query_as(CURRENT_KEY_SQL)
            .bind(authority.realm())
            .bind(authority.issuer())
            .fetch_optional(&self.pool)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Unavailable)?;
        row.snapshot(authority)
    }
    /// Publish preannounced and retained public keys independently of issuance
    /// disable, so stopping new grants does not silently erase promised overlap.
    pub async fn issuer_public_keys(
        &self,
        authority: &IssuerAuthority,
    ) -> Result<Vec<IssuerPublicKey>> {
        let rows: Vec<KeyRow> = sqlx::query_as(
            r#"
            SELECT id,public_jwk,sign_from_us,sign_until_us,verify_until_us,ready_at_us,enabled
            FROM auth_issuer_keys WHERE realm_id=$1 AND issuer=$2 AND enabled
              AND verify_until_us>(extract(epoch FROM clock_timestamp())*1000000)::bigint
            ORDER BY id LIMIT $3
        "#,
        )
        .bind(authority.realm())
        .bind(authority.issuer())
        .bind(MAX_ISSUER_PUBLISHED_KEYS + 1)
        .fetch_all(&self.pool)
        .await
        .map_err(unavailable)?;
        if rows.is_empty() || rows.len() as i64 > MAX_ISSUER_PUBLISHED_KEYS {
            return Err(Error::Unavailable);
        }
        rows.into_iter()
            .map(|row| Ok(row.publication(authority)?.key().clone()))
            .collect()
    }
}
