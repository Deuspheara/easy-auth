use super::{super::subject, notices};
use crate::{Postgres, audit, sessions::FreshSessionSnapshot, unavailable};
use auth_core::{AuditEvent, Error, Result, Verifier};
use sqlx::{Row, Transaction};
use uuid::Uuid;

struct Target {
    connection: Uuid,
    client: Uuid,
    issuer: String,
    subject: String,
    owner: Uuid,
}
impl Target {
    async fn load(store: &Postgres, realm: Uuid, identity: Uuid) -> Result<Self> {
        let row=sqlx::query("SELECT connection_id,client_id,issuer,subject,user_id FROM auth_oidc_identities WHERE realm_id=$1 AND id=$2").bind(realm).bind(identity).fetch_optional(&store.pool).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        Ok(Self {
            connection: row.try_get("connection_id").map_err(unavailable)?,
            client: row.try_get("client_id").map_err(unavailable)?,
            issuer: row.try_get("issuer").map_err(unavailable)?,
            subject: row.try_get("subject").map_err(unavailable)?,
            owner: row.try_get("user_id").map_err(unavailable)?,
        })
    }
    async fn lock(
        &self,
        tx: &mut Transaction<'_, sqlx::Postgres>,
        realm: Uuid,
        identity: Uuid,
    ) -> Result<()> {
        let id:Option<Uuid>=sqlx::query_scalar("SELECT id FROM auth_oidc_identities WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND connection_id=$4 AND client_id=$5 AND issuer=$6 AND subject=$7 FOR UPDATE")
            .bind(realm).bind(identity).bind(self.owner).bind(self.connection).bind(self.client).bind(&self.issuer).bind(&self.subject).fetch_optional(&mut **tx).await.map_err(unavailable)?;
        if id != Some(identity) {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

pub(super) async fn finish(
    store: &Postgres,
    realm: Uuid,
    current: Verifier,
    identity: Uuid,
) -> Result<()> {
    let snapshot = FreshSessionSnapshot::load(&store.pool, realm, current).await?;
    let target = Target::load(store, realm, identity).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    // Removing a disabled/stale target is allowed, but source-before-owner lock
    // order still serializes its registration with administrative changes.
    let registered:Option<Uuid>=sqlx::query_scalar("SELECT id FROM auth_oauth_connections WHERE realm_id=$1 AND id=$2 AND client_id=$3 FOR SHARE")
        .bind(realm).bind(target.connection).bind(target.client).fetch_optional(&mut *tx).await.map_err(unavailable)?;
    if registered != Some(target.connection) {
        return Err(Error::Unauthorized);
    }
    subject::lock(
        &mut tx,
        realm,
        target.connection,
        target.client,
        &target.issuer,
        &target.subject,
    )
    .await?;
    let caller = snapshot.lock(&mut tx).await?;
    if caller.user != target.owner {
        return Err(Error::Unauthorized);
    }
    target.lock(&mut tx, realm, identity).await?;
    let current_identity: Option<Uuid> = sqlx::query_scalar(
        "SELECT oidc_identity_id FROM auth_sessions WHERE realm_id=$1 AND id=$2 AND user_id=$3",
    )
    .bind(realm)
    .bind(caller.session)
    .bind(caller.user)
    .fetch_one(&mut *tx)
    .await
    .map_err(unavailable)?;
    // The authorizing credential must remain. Actual fresh current-source proof
    // is stronger evidence than a count of disabled or unusable inventory rows.
    if caller.method == "oidc" && current_identity == Some(identity) {
        return Err(Error::Unauthorized);
    }
    caller.deadline.check(&mut tx).await?;
    // Preserve audit-referenced historical rows and original OIDC provenance.
    // Source validation requires the actual identity even on an unrevoked row.
    sqlx::query("UPDATE auth_sessions SET revoked_at=coalesce(revoked_at,clock_timestamp()),oidc_identity_id=NULL WHERE realm_id=$1 AND user_id=$2 AND oidc_identity_id=$3")
        .bind(realm).bind(caller.user).bind(identity).execute(&mut *tx).await.map_err(unavailable)?;
    let removed =
        sqlx::query("DELETE FROM auth_oidc_identities WHERE realm_id=$1 AND user_id=$2 AND id=$3")
            .bind(realm)
            .bind(caller.user)
            .bind(identity)
            .execute(&mut *tx)
            .await
            .map_err(unavailable)?
            .rows_affected();
    if removed != 1 {
        return Err(Error::Unauthorized);
    }
    subject::remember_deleted(
        &mut tx,
        realm,
        target.connection,
        target.client,
        &target.issuer,
        &target.subject,
    )
    .await?;
    audit::record(
        &mut tx,
        realm,
        AuditEvent::OidcIdentityUnlinked {
            user_id: caller.user,
            actor_session_id: caller.session,
            identity_id: identity,
        },
    )
    .await?;
    notices::enqueue(&mut tx, realm, caller.user).await?;
    caller.deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)
}
