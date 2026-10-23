//! Explicit native grant source/owner locking, never ordinary cookie validation.
use super::{ownership::Owner, source::Source};
use crate::{locking::lock_email, unavailable};
use auth_core::{AuthenticationPolicy, Error, IssuerNativeRefreshPolicy, Result, Verifier};
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

/// Caller selects this path only from an existing exact realm/issuer/client
/// family credential. This snapshot merely chooses lock order and grants nothing.
pub(crate) struct DelegatedSessionSnapshot {
    realm: Uuid,
    owner: Owner,
    session: Uuid,
    token: Verifier,
}
impl DelegatedSessionSnapshot {
    pub(crate) async fn load(
        pool: &PgPool,
        realm: Uuid,
        user: Uuid,
        session: Uuid,
    ) -> Result<Self> {
        let token: Vec<u8> = sqlx::query_scalar(
            "SELECT token_hash FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3",
        )
        .bind(realm)
        .bind(user)
        .bind(session)
        .fetch_optional(pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        let token: Verifier = token.try_into().map_err(|_| Error::Unavailable)?;
        let owner = Owner::load(pool, realm, token).await?;
        if owner.user != user {
            return Err(Error::Unauthorized);
        }
        Ok(Self {
            realm,
            owner,
            session,
            token,
        })
    }
    /// Uses only native family absolute/idle authority; never touches or extends
    /// the cookie's own freshness, idle time or absolute expiry. Original source,
    /// owner policy, session/method/time and revocation remain mandatory.
    pub(crate) async fn lock(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        policy: &IssuerNativeRefreshPolicy,
        method: &str,
        authenticated_at_us: i64,
        grant_expires_at_us: i64,
    ) -> Result<()> {
        if policy.authority().realm() != self.realm {
            return Err(Error::Unauthorized);
        }
        let source = Source::lock(tx, self.realm, self.token).await?;
        if source.method() != method {
            return Err(Error::Unauthorized);
        }
        if let Some(email) = &self.owner.email {
            lock_email(tx, self.realm, email).await?;
        }
        let owner_policy:String=sqlx::query_scalar("SELECT authentication_policy FROM auth_users WHERE realm_id=$1 AND id=$2 AND email IS NOT DISTINCT FROM $3::text FOR UPDATE")
            .bind(self.realm).bind(self.owner.user).bind(&self.owner.email).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        if !policy.permits_authentication(
            AuthenticationPolicy::try_from(owner_policy.as_str())?,
            method,
        ) {
            return Err(Error::Unauthorized);
        }
        sqlx::query("SELECT id FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3 AND token_hash=$4 FOR UPDATE")
            .bind(self.realm).bind(self.owner.user).bind(self.session).bind(self.token.as_slice()).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        #[cfg(any(feature = "oidc-identities", feature = "saml-identities"))]
        source.recheck(tx, self.realm, self.token).await?;
        let valid:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3 AND token_hash=$4 AND revoked_at IS NULL AND authentication_method=$5 AND isfinite(authenticated_at) AND authenticated_at<=clock_timestamp() AND (extract(epoch FROM authenticated_at)*1000000)::bigint=$6 AND expires_at>clock_timestamp() AND (extract(epoch FROM expires_at)*1000000)::bigint>=$7)")
            .bind(self.realm).bind(self.owner.user).bind(self.session).bind(self.token.as_slice()).bind(method).bind(authenticated_at_us).bind(grant_expires_at_us)
            .fetch_one(&mut **tx).await.map_err(unavailable)?;
        if !valid {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
