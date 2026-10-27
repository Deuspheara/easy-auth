use crate::unavailable;
use auth_core::{Error, Result, Verifier};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Current provider configuration/policy are locked before any owner/session.
pub(in crate::sessions) struct LockedSource {
    identity: Uuid,
    revision: Uuid,
    connection: Uuid,
    client: Uuid,
    issuer: String,
}

impl LockedSource {
    #[cfg(feature = "oidc-linking")]
    pub(in crate::sessions) async fn explicitly_linked(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        owner: Uuid,
    ) -> Result<bool> {
        sqlx::query_scalar("SELECT explicitly_linked FROM auth_oidc_identities WHERE realm_id=$1 AND id=$2 AND user_id=$3")
            .bind(realm).bind(self.identity).bind(owner).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)
    }
    pub(in crate::sessions) async fn lock(
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        current: Verifier,
    ) -> Result<Self> {
        let (identity,revision,connection,client,issuer) = sqlx::query_as(r#"
            SELECT e.id,c.revision,c.id,c.client_id,c.issuer
            FROM auth_sessions s
            JOIN auth_oidc_identities e ON e.realm_id=s.realm_id AND e.id=s.oidc_identity_id AND e.user_id=s.user_id
            JOIN auth_oauth_connections c ON c.realm_id=e.realm_id AND c.id=e.connection_id AND c.client_id=e.client_id
            WHERE s.realm_id=$1 AND s.token_hash=$2 AND s.authentication_method='oidc'
              AND c.enabled AND c.revision=s.oidc_revision AND c.issuer=e.issuer
            FOR SHARE OF c
        "#)
        .bind(realm)
        .bind(current.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        let source = Self {
            identity,
            revision,
            connection,
            client,
            issuer,
        };
        let policy: Option<Uuid> = sqlx::query_scalar("SELECT revision FROM auth_oidc_identity_policies WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND revision=$4 FOR SHARE")
        .bind(realm)
        .bind(source.connection)
        .bind(source.client)
        .bind(source.revision)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?;
        if policy != Some(source.revision) {
            return Err(Error::Unauthorized);
        }
        Ok(source)
    }
    pub(in crate::sessions) async fn recheck(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        current: Verifier,
    ) -> Result<()> {
        let valid: bool = sqlx::query_scalar(
            r#"
            SELECT EXISTS(SELECT 1 FROM auth_sessions s JOIN auth_oidc_identities e
              ON e.realm_id=s.realm_id AND e.id=s.oidc_identity_id AND e.user_id=s.user_id
            WHERE s.realm_id=$1 AND s.token_hash=$2 AND s.authentication_method='oidc'
              AND s.oidc_identity_id=$3 AND s.oidc_revision=$4
              AND e.connection_id=$5 AND e.client_id=$6 AND e.issuer=$7)
        "#,
        )
        .bind(realm)
        .bind(current.as_slice())
        .bind(self.identity)
        .bind(self.revision)
        .bind(self.connection)
        .bind(self.client)
        .bind(&self.issuer)
        .fetch_one(&mut **tx)
        .await
        .map_err(unavailable)?;
        if !valid {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    /// Owner is already locked. Unknown provider authentication time cannot
    /// become freshness merely because the local session was issued recently.
    pub(in crate::sessions) async fn fresh_session(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        owner: Uuid,
        current: Verifier,
    ) -> Result<Uuid> {
        self.recheck(tx, realm, current).await?;
        let policy: String = sqlx::query_scalar(
            "SELECT authentication_policy FROM auth_users WHERE realm_id=$1 AND id=$2",
        )
        .bind(realm)
        .bind(owner)
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        let policy = auth_core::AuthenticationPolicy::try_from(policy.as_str())?;
        #[cfg(feature = "oidc-linking")]
        let linked = if policy == auth_core::AuthenticationPolicy::Mailbox {
            self.explicitly_linked(tx, realm, owner).await?
        } else {
            false
        };
        #[cfg(not(feature = "oidc-linking"))]
        let linked = false;
        if !policy.permits_session_method("oidc", linked) {
            return Err(Error::Unauthorized);
        }
        sqlx::query_scalar(r#"
            SELECT s.id FROM auth_sessions s JOIN auth_users u ON u.realm_id=s.realm_id AND u.id=s.user_id
            WHERE s.realm_id=$1 AND s.user_id=$2 AND s.token_hash=$3
              AND s.authentication_method='oidc' AND s.revoked_at IS NULL
              AND s.expires_at>clock_timestamp() AND s.last_seen_at>clock_timestamp()-interval '30 minutes'
              AND isfinite(s.authenticated_at) AND s.authenticated_at>clock_timestamp()-interval '5 minutes'
              AND s.authenticated_at<=clock_timestamp()
            FOR UPDATE OF s
        "#)
        .bind(realm)
        .bind(owner)
        .bind(current.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?.ok_or(Error::Unauthorized)
    }
}
