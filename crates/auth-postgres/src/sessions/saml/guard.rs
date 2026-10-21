use crate::unavailable;
use auth_core::{Error, Result, Verifier};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

/// Source/policy row locks precede owner/session locks for every protected use.
pub(in crate::sessions) struct LockedSource {
    identity: Uuid,
    revision: Uuid,
    connection: Uuid,
    client: Uuid,
    idp: String,
    sp: String,
}
impl LockedSource {
    pub(in crate::sessions) async fn lock(
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        current: Verifier,
    ) -> Result<Self> {
        let (identity,revision,connection,client,idp,sp) = sqlx::query_as(r#"
            SELECT e.id,c.revision,c.id,c.client_id,c.idp_entity,c.sp_entity FROM auth_sessions s
            JOIN auth_saml_identities e ON e.realm_id=s.realm_id AND e.id=s.saml_identity_id AND e.user_id=s.user_id
            JOIN auth_saml_registrations c ON c.realm_id=e.realm_id AND c.id=e.connection_id AND c.client_id=e.client_id
            JOIN auth_saml_identity_policies p ON p.realm_id=c.realm_id AND p.connection_id=c.id AND p.client_id=c.client_id
            WHERE s.realm_id=$1 AND s.token_hash=$2 AND s.authentication_method='saml'
              AND c.enabled AND c.revision=s.saml_revision AND p.revision=c.revision AND p.jit IN ('deny','allow')
              AND e.idp_entity=c.idp_entity AND e.sp_entity=c.sp_entity
            FOR SHARE OF c,p
        "#).bind(realm).bind(current.as_slice()).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
        Ok(Self {
            identity,
            revision,
            connection,
            client,
            idp,
            sp,
        })
    }
    pub(in crate::sessions) async fn recheck(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        current: Verifier,
    ) -> Result<()> {
        let valid: bool = sqlx::query_scalar(r#"
            SELECT EXISTS(SELECT 1 FROM auth_sessions s JOIN auth_saml_identities e
              ON e.realm_id=s.realm_id AND e.id=s.saml_identity_id AND e.user_id=s.user_id
            WHERE s.realm_id=$1 AND s.token_hash=$2 AND s.authentication_method='saml'
              AND s.saml_identity_id=$3 AND s.saml_revision=$4 AND e.connection_id=$5 AND e.client_id=$6
              AND e.idp_entity=$7 AND e.sp_entity=$8)
        "#).bind(realm).bind(current.as_slice()).bind(self.identity).bind(self.revision).bind(self.connection).bind(self.client)
            .bind(&self.idp).bind(&self.sp).fetch_one(&mut **tx).await.map_err(unavailable)?;
        if !valid {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
    pub(in crate::sessions) async fn fresh_session(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        owner: Uuid,
        current: Verifier,
    ) -> Result<Uuid> {
        self.recheck(tx, realm, current).await?;
        sqlx::query_scalar(r#"
            SELECT s.id FROM auth_sessions s JOIN auth_users u ON u.realm_id=s.realm_id AND u.id=s.user_id
            WHERE s.realm_id=$1 AND s.user_id=$2 AND s.token_hash=$3 AND u.authentication_policy='provider_required'
              AND s.authentication_method='saml' AND s.revoked_at IS NULL
              AND s.expires_at>clock_timestamp() AND s.last_seen_at>clock_timestamp()-interval '30 minutes'
              AND isfinite(s.authenticated_at) AND s.authenticated_at>clock_timestamp()-interval '5 minutes'
              AND s.authenticated_at<=clock_timestamp() FOR UPDATE OF s
        "#).bind(realm).bind(owner).bind(current.as_slice()).fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)
    }
}
