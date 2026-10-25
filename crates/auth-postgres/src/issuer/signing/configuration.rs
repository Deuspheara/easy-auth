use super::state::{self, KeyRow};
use crate::{Postgres, unavailable};
use auth_core::{
    Error, ISSUER_KEY_PROPAGATION_SECONDS, IssuerAuthority, IssuerKeyPublication,
    MAX_ISSUER_PUBLISHED_KEYS, Result,
};
use uuid::Uuid;

impl Postgres {
    /// Explicit trusted public-key publication. Creates a disabled namespace;
    /// neither selects a signer nor re-enables an operator-disabled definition.
    pub async fn publish_issuer_key(
        &self,
        input: &IssuerKeyPublication,
    ) -> Result<IssuerKeyPublication> {
        let authority = input.authority();
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        sqlx::query("INSERT INTO auth_issuer_key_sets(realm_id,issuer,revision) VALUES($1,$2,$3) ON CONFLICT DO NOTHING")
            .bind(authority.realm()).bind(authority.issuer()).bind(Uuid::new_v4()).execute(&mut *tx).await.map_err(unavailable)?;
        state::lock_namespace(&mut tx, authority).await?;
        let now = state::now(&mut tx).await?;
        let ready_at = propagation_deadline(now)?;
        if input.sign_until_us() <= now {
            return Err(Error::InvalidInput);
        }
        let (live,existing):(i64,bool)=sqlx::query_as("SELECT count(*) FILTER(WHERE enabled AND verify_until_us>$3),coalesce(bool_or(id=$4 AND enabled AND verify_until_us>$3),false) FROM auth_issuer_keys WHERE realm_id=$1 AND issuer=$2")
            .bind(authority.realm()).bind(authority.issuer()).bind(now).bind(input.key().id()).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if !existing && live >= MAX_ISSUER_PUBLISHED_KEYS {
            return Err(Error::RateLimited);
        }
        let row:KeyRow=sqlx::query_as(r#"
            INSERT INTO auth_issuer_keys(realm_id,issuer,id,public_jwk,sign_from_us,sign_until_us,verify_until_us,ready_at_us)
            VALUES($1,$2,$3,$4,$5,$6,$7,$8)
            ON CONFLICT(realm_id,issuer,id) DO UPDATE SET
                sign_from_us=EXCLUDED.sign_from_us,sign_until_us=EXCLUDED.sign_until_us,
                verify_until_us=greatest(auth_issuer_keys.verify_until_us,EXCLUDED.verify_until_us),
                ready_at_us=CASE WHEN auth_issuer_keys.enabled AND auth_issuer_keys.verify_until_us>$9
                    THEN auth_issuer_keys.ready_at_us ELSE EXCLUDED.ready_at_us END
            WHERE auth_issuer_keys.public_jwk=EXCLUDED.public_jwk
            RETURNING id,public_jwk,sign_from_us,sign_until_us,verify_until_us,ready_at_us,enabled
        "#).bind(authority.realm()).bind(authority.issuer()).bind(input.key().id()).bind(input.key().document())
            .bind(input.sign_from_us()).bind(input.sign_until_us()).bind(input.verify_until_us()).bind(ready_at).bind(now)
            .fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(Error::InvalidInput)?;
        let publication = row.publication(authority)?;
        state::revise(&mut tx, authority).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(publication)
    }
    /// First bootstrap may activate immediately. Replacement selection requires
    /// an actual database-observed prepublication interval, not a caller date.
    pub async fn activate_issuer_key(&self, authority: &IssuerAuthority, id: Uuid) -> Result<Uuid> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        let (_, bootstrapped, _) = state::lock_namespace(&mut tx, authority).await?;
        let row:KeyRow=sqlx::query_as("SELECT id,public_jwk,sign_from_us,sign_until_us,verify_until_us,ready_at_us,enabled FROM auth_issuer_keys WHERE realm_id=$1 AND issuer=$2 AND id=$3 FOR UPDATE")
            .bind(authority.realm()).bind(authority.issuer()).bind(id).fetch_optional(&mut *tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        row.publication(authority)?;
        let now = state::now(&mut tx).await?;
        if !row.enabled
            || now < row.sign_from_us
            || now >= row.sign_until_us
            || (bootstrapped && now < row.ready_at_us)
        {
            return Err(Error::Unauthorized);
        }
        if !bootstrapped {
            // Only the first namespace bootstrap may waive propagation. Later
            // reenable/reopening cannot reuse this historical bootstrap privilege.
            sqlx::query("UPDATE auth_issuer_keys SET ready_at_us=$4 WHERE realm_id=$1 AND issuer=$2 AND id=$3")
                .bind(authority.realm()).bind(authority.issuer()).bind(id).bind(now).execute(&mut *tx).await.map_err(unavailable)?;
        }
        let revision = Uuid::new_v4();
        sqlx::query("UPDATE auth_issuer_key_sets SET active_key=$3,bootstrapped=true,revision=$4 WHERE realm_id=$1 AND issuer=$2")
            .bind(authority.realm()).bind(authority.issuer()).bind(id).bind(revision).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)?;
        Ok(revision)
    }
    /// Enable only the exact latest trusted namespace revision and a live selected
    /// key. Private-material equality remains required inside actual issuance.
    pub async fn enable_issuer_signing(
        &self,
        authority: &IssuerAuthority,
        revision: Uuid,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        state::lock_namespace(&mut tx, authority).await?;
        let changed = sqlx::query(
            r#"
            UPDATE auth_issuer_key_sets s SET enabled=true
            WHERE s.realm_id=$1 AND s.issuer=$2 AND s.revision=$3
              AND EXISTS(SELECT 1 FROM auth_issuer_keys k WHERE k.realm_id=s.realm_id
                AND k.issuer=s.issuer AND k.id=s.active_key AND k.enabled
                AND k.ready_at_us<=(extract(epoch FROM clock_timestamp())*1000000)::bigint
                AND k.sign_from_us<=(extract(epoch FROM clock_timestamp())*1000000)::bigint
                AND k.sign_until_us>(extract(epoch FROM clock_timestamp())*1000000)::bigint)
        "#,
        )
        .bind(authority.realm())
        .bind(authority.issuer())
        .bind(revision)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(Error::Unauthorized);
        }
        tx.commit().await.map_err(unavailable)
    }
    pub async fn disable_issuer_signing(&self, authority: &IssuerAuthority) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        state::lock_namespace(&mut tx, authority).await?;
        sqlx::query("UPDATE auth_issuer_key_sets SET enabled=false,revision=$3 WHERE realm_id=$1 AND issuer=$2")
            .bind(authority.realm()).bind(authority.issuer()).bind(Uuid::new_v4()).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }
    /// Explicit exact-definition key re-enable; never selects it or re-enables
    /// the whole issuer. Namespace locking also preserves the publication bound.
    pub async fn enable_issuer_key(&self, input: &IssuerKeyPublication) -> Result<()> {
        let authority = input.authority();
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        state::lock_namespace(&mut tx, authority).await?;
        let now = state::now(&mut tx).await?;
        let ready_at = propagation_deadline(now)?;
        let others:i64=sqlx::query_scalar("SELECT count(*) FROM auth_issuer_keys WHERE realm_id=$1 AND issuer=$2 AND id<>$3 AND enabled AND verify_until_us>$4")
            .bind(authority.realm()).bind(authority.issuer()).bind(input.key().id()).bind(now).fetch_one(&mut *tx).await.map_err(unavailable)?;
        if others >= MAX_ISSUER_PUBLISHED_KEYS {
            return Err(Error::RateLimited);
        }
        let changed = sqlx::query(
            r#"
            UPDATE auth_issuer_keys SET enabled=true,
              ready_at_us=CASE WHEN enabled AND verify_until_us>$8 THEN ready_at_us ELSE $9 END
            WHERE realm_id=$1 AND issuer=$2 AND id=$3
              AND public_jwk=$4 AND sign_from_us=$5 AND sign_until_us=$6 AND verify_until_us=$7
              AND sign_until_us>$8
        "#,
        )
        .bind(authority.realm())
        .bind(authority.issuer())
        .bind(input.key().id())
        .bind(input.key().document())
        .bind(input.sign_from_us())
        .bind(input.sign_until_us())
        .bind(input.verify_until_us())
        .bind(now)
        .bind(ready_at)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(Error::Unauthorized);
        }
        state::revise(&mut tx, authority).await?;
        tx.commit().await.map_err(unavailable)
    }
    pub async fn disable_issuer_key(&self, authority: &IssuerAuthority, id: Uuid) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        state::lock_namespace(&mut tx, authority).await?;
        let changed = sqlx::query(
            "UPDATE auth_issuer_keys SET enabled=false WHERE realm_id=$1 AND issuer=$2 AND id=$3",
        )
        .bind(authority.realm())
        .bind(authority.issuer())
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(unavailable)?
        .rows_affected();
        if changed != 1 {
            return Err(Error::Unauthorized);
        }
        state::revise(&mut tx, authority).await?;
        tx.commit().await.map_err(unavailable)
    }
}

fn propagation_deadline(now: i64) -> Result<i64> {
    now.checked_add(ISSUER_KEY_PROPAGATION_SECONDS * 1_000_000)
        .ok_or(Error::Unavailable)
}
