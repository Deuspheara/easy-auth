use super::state::{self, AuthorizationState};
use crate::{
    Postgres, audit,
    deadlines::Deadline,
    sessions::{FreshSessionAuthorization, FreshSessionSnapshot},
    unavailable,
};
use auth_core::{
    AuditEvent, Error, IssuerCodeRedemption, IssuerGrantData, IssuerTokenError, IssuerTokenResult,
    Result, Verifier,
};
use sqlx::{Postgres as Pg, Transaction};

pub(in crate::issuer) struct CodeCandidate {
    original: AuthorizationState,
    owner: FreshSessionSnapshot,
}
impl CodeCandidate {
    pub(in crate::issuer) async fn read(
        store: &Postgres,
        request: &IssuerCodeRedemption<'_>,
    ) -> Result<Option<Self>> {
        if !request.client.supports_online_authorization() {
            return Err(Error::Unauthorized);
        }
        let Some(original) = state::code(store, request).await? else {
            return Ok(None);
        };
        if original.native_refresh {
            return Err(Error::Unauthorized);
        }
        let token: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT token_hash FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3",
        )
        .bind(request.authority.realm())
        .bind(original.user_id)
        .bind(original.session_id)
        .fetch_optional(&store.pool)
        .await
        .map_err(unavailable)?;
        let Some(token) = token else {
            return Ok(None);
        };
        let token: Verifier = token.try_into().map_err(|_| Error::Unavailable)?;
        let owner =
            match FreshSessionSnapshot::load(&store.pool, request.authority.realm(), token).await {
                Ok(owner) => owner,
                Err(Error::Unauthorized) => return Ok(None),
                Err(error) => return Err(error),
            };
        Ok(Some(Self { original, owner }))
    }
}

pub(in crate::issuer) struct LockedCode {
    state: AuthorizationState,
    caller: FreshSessionAuthorization,
    deadline: Deadline,
}
impl CodeCandidate {
    /// Caller holds the exact current client/credential lock before this method.
    pub(in crate::issuer) async fn lock(
        self,
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerCodeRedemption<'_>,
    ) -> IssuerTokenResult<LockedCode> {
        let caller = self.owner.lock(tx).await?;
        let locked = state::lock_code(tx, request, &caller).await?;
        if locked != self.original {
            return Err(IssuerTokenError::InvalidGrant);
        }
        let code_expiry = locked
            .code_expires_at_us
            .ok_or(IssuerTokenError::Unavailable)?;
        let deadline = Deadline::proof(caller.deadline.expires_us())
            .with_proof(code_expiry)
            .with_proof(locked.session_cap_us)
            .with_proof(
                self.original
                    .code_expires_at_us
                    .ok_or(IssuerTokenError::Unavailable)?,
            )
            .with_proof(self.original.session_cap_us);
        Ok(LockedCode {
            state: locked,
            caller,
            deadline,
        })
    }
}
impl LockedCode {
    pub(in crate::issuer) fn expires_at_us(&self) -> i64 {
        self.deadline.expires_us()
    }
    pub(in crate::issuer) fn facts(&self, issued_at_us: i64) -> IssuerTokenResult<IssuerGrantData> {
        Ok(IssuerGrantData {
            authorization: self.state.id,
            owner: self.caller.user,
            session: self.caller.session,
            subject: self.state.subject.ok_or(IssuerTokenError::Unavailable)?,
            nonce: self
                .state
                .nonce
                .as_ref()
                .ok_or(IssuerTokenError::Unavailable)?
                .clone(),
            authentication_method: self.caller.method.clone(),
            authenticated_at_us: self.caller.authenticated_at_us,
            issued_at_us,
            expires_at_us: self.deadline.expires_us(),
            session_expires_at_us: self.state.session_cap_us,
        })
    }
    #[cfg(feature = "issuer-signing")]
    pub(in crate::issuer) fn matches_grant(
        &self,
        grant: &IssuerGrantData,
    ) -> IssuerTokenResult<bool> {
        let current = self.facts(grant.issued_at_us)?;
        Ok(current.authorization == grant.authorization
            && current.owner == grant.owner
            && current.session == grant.session
            && current.subject == grant.subject
            && current.nonce == grant.nonce
            && current.authentication_method == grant.authentication_method
            && current.authenticated_at_us == grant.authenticated_at_us
            && current.session_expires_at_us == grant.session_expires_at_us)
    }
    #[cfg(feature = "issuer-signing")]
    pub(in crate::issuer) async fn snapshot(
        &self,
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerCodeRedemption<'_>,
    ) -> Result<String> {
        // PostgreSQL's own canonical row representation freezes every original
        // field across the unlocked signing interval. Never log/serialize it to HTTP.
        sqlx::query_scalar("SELECT to_jsonb(a)::text FROM auth_issuer_authorizations a WHERE realm_id=$1 AND id=$2")
            .bind(request.authority.realm()).bind(self.state.id).fetch_one(&mut **tx).await.map_err(unavailable)
    }
    pub(in crate::issuer) async fn consume(
        &self,
        tx: &mut Transaction<'_, Pg>,
        request: &IssuerCodeRedemption<'_>,
        now: i64,
    ) -> Result<()> {
        sqlx::query(
            r#"
            UPDATE auth_issuer_authorizations
            SET status='consumed',consumed_at_us=$3,state=NULL,nonce=NULL,pkce_challenge=NULL
            WHERE realm_id=$1 AND id=$2 AND status='approved'
        "#,
        )
        .bind(request.authority.realm())
        .bind(self.state.id)
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(unavailable)?;
        audit::record(
            tx,
            request.authority.realm(),
            AuditEvent::IssuerCodeRedeemed {
                user_id: self.caller.user,
                actor_session_id: self.caller.session,
                client_id: request.client.client(),
                authorization_id: self.state.id,
            },
        )
        .await
    }
    pub(in crate::issuer) async fn check(&self, tx: &mut Transaction<'_, Pg>) -> Result<()> {
        self.deadline.check(tx).await
    }
}
