use crate::{Postgres, unavailable};
use auth_core::{Error, OAuthConnection, OAuthMixupDefense, Result};
use sqlx::{Postgres as Pg, Transaction};
use uuid::Uuid;

fn defense(connection: &OAuthConnection) -> &'static str {
    match connection.defense() {
        OAuthMixupDefense::RequireIssuer => "issuer",
        OAuthMixupDefense::DedicatedRedirect => "dedicated_redirect",
    }
}

impl Postgres {
    /// Trusted administrative composition only. Every application receives a new
    /// revision, including stale configuration objects. Existing disable is retained.
    pub async fn configure_oauth_connection(
        &self,
        input: &OAuthConnection,
    ) -> Result<OAuthConnection> {
        let connection = input.reconfigured();
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        replace(&mut tx, &connection).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(connection)
    }

    pub async fn disable_oauth_connection(
        &self,
        realm: Uuid,
        connection: Uuid,
        client: Uuid,
    ) -> Result<()> {
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // Invalidate contexts already claimed before disable, even after re-enable.
        sqlx::query("UPDATE auth_oauth_connections SET enabled=false,revision=$4 WHERE realm_id=$1 AND id=$2 AND client_id=$3")
            .bind(realm).bind(connection).bind(client).bind(Uuid::new_v4()).execute(&mut *tx).await.map_err(unavailable)?;
        sqlx::query("DELETE FROM auth_oauth_transactions WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3")
            .bind(realm).bind(connection).bind(client).execute(&mut *tx).await.map_err(unavailable)?;
        tx.commit().await.map_err(unavailable)
    }

    /// Explicit administrative re-enable of the latest persisted configuration.
    /// Configure never implicitly clears an existing disable.
    pub async fn enable_oauth_connection(&self, connection: &OAuthConnection) -> Result<()> {
        let updated=sqlx::query("UPDATE auth_oauth_connections SET enabled=true WHERE realm_id=$1 AND id=$2 AND client_id=$3 AND revision=$4")
            .bind(connection.realm()).bind(connection.connection()).bind(connection.client()).bind(connection.revision())
            .execute(&self.pool).await.map_err(unavailable)?.rows_affected();
        if updated != 1 {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}

/// Persist a freshly allocated configuration revision inside the caller's
/// transaction. Retain disable and cancel previous-revision pending state together.
pub(super) async fn replace(
    tx: &mut Transaction<'_, Pg>,
    connection: &OAuthConnection,
) -> Result<()> {
    sqlx::query(
        r#"
        INSERT INTO auth_oauth_connections(realm_id,id,client_id,revision,issuer,provider_client,redirect_uri,defense,enabled)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true)
        ON CONFLICT (realm_id,id,client_id) DO UPDATE SET
          revision=EXCLUDED.revision,issuer=EXCLUDED.issuer,provider_client=EXCLUDED.provider_client,
          redirect_uri=EXCLUDED.redirect_uri,defense=EXCLUDED.defense
        "#,
    ).bind(connection.realm()).bind(connection.connection()).bind(connection.client())
        .bind(connection.revision()).bind(connection.issuer()).bind(connection.provider_client())
        .bind(connection.redirect()).bind(defense(connection)).execute(&mut **tx).await.map_err(unavailable)?;
    sqlx::query("DELETE FROM auth_oauth_transactions WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision<>$4")
        .bind(connection.realm()).bind(connection.connection()).bind(connection.client()).bind(connection.revision())
        .execute(&mut **tx).await.map_err(unavailable)?;
    Ok(())
}

pub(super) async fn lock(tx: &mut Transaction<'_, Pg>, connection: &OAuthConnection) -> Result<()> {
    let enabled: Option<bool> = sqlx::query_scalar(
        r#"
        SELECT enabled FROM auth_oauth_connections WHERE realm_id=$1 AND id=$2 AND client_id=$3
          AND revision=$4 AND issuer=$5 AND provider_client=$6 AND redirect_uri=$7 AND defense=$8 FOR SHARE
        "#,
    ).bind(connection.realm()).bind(connection.connection()).bind(connection.client())
        .bind(connection.revision()).bind(connection.issuer()).bind(connection.provider_client())
        .bind(connection.redirect()).bind(defense(connection)).fetch_optional(&mut **tx).await.map_err(unavailable)?;
    if enabled != Some(true) {
        return Err(Error::Unauthorized);
    }
    Ok(())
}

#[cfg(feature = "oidc-egress")]
pub(super) async fn check(pool: &sqlx::PgPool, connection: &OAuthConnection) -> Result<()> {
    let mut tx = pool.begin().await.map_err(unavailable)?;
    lock(&mut tx, connection).await?;
    tx.commit().await.map_err(unavailable)
}

/// Lock a registry key for startup loading; this is not a full definition check.
#[cfg(feature = "oidc-identities")]
pub(super) async fn current_revision(
    tx: &mut Transaction<'_, Pg>,
    connection: &OAuthConnection,
) -> Result<Option<Uuid>> {
    sqlx::query_scalar("SELECT revision FROM auth_oauth_connections WHERE realm_id=$1 AND id=$2 AND client_id=$3 FOR SHARE")
        .bind(connection.realm()).bind(connection.connection()).bind(connection.client())
        .fetch_optional(&mut **tx).await.map_err(unavailable)
}

/// Serialize only first creation. A conflicting registry key remains untouched;
/// a globally conflicting callback still fails instead of selecting another key.
#[cfg(feature = "oidc-identities")]
pub(super) async fn insert_initial(
    tx: &mut Transaction<'_, Pg>,
    connection: &OAuthConnection,
) -> Result<bool> {
    let inserted = sqlx::query(
        r#"
        INSERT INTO auth_oauth_connections(realm_id,id,client_id,revision,issuer,provider_client,redirect_uri,defense,enabled)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,true)
        ON CONFLICT (realm_id,id,client_id) DO NOTHING
        "#,
    ).bind(connection.realm()).bind(connection.connection()).bind(connection.client())
        .bind(connection.revision()).bind(connection.issuer()).bind(connection.provider_client())
        .bind(connection.redirect()).bind(defense(connection))
        .execute(&mut **tx).await.map_err(unavailable)?.rows_affected();
    Ok(inserted == 1)
}
