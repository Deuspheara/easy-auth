use super::state::{self, AuthorizationState};
use crate::{
    Postgres,
    deadlines::Deadline,
    issuer::configuration,
    sessions::{FreshSessionAuthorization, FreshSessionSnapshot},
};
use auth_core::{
    Error, IssuerAuthorizationDestination, IssuerClientRegistration, IssuerConsentProof, Result,
};
use sqlx::{Postgres as Pg, Transaction};

pub(super) struct DecisionCandidate {
    pub(super) original: AuthorizationState,
    pub(super) client: IssuerClientRegistration,
    pub(super) owner: FreshSessionSnapshot,
}
impl DecisionCandidate {
    pub(super) async fn load(store: &Postgres, proof: &IssuerConsentProof<'_>) -> Result<Self> {
        let original = state::pending(store, proof).await?;
        let client = store
            .load_issuer_client(proof.authority.realm(), original.client_id)
            .await?;
        if original.native_refresh
            || !client.supports_online_authorization()
            || client.revision() != original.client_revision
        {
            return Err(Error::Unauthorized);
        }
        let owner =
            FreshSessionSnapshot::load(&store.pool, proof.authority.realm(), proof.current).await?;
        Ok(Self {
            original,
            client,
            owner,
        })
    }
    pub(super) async fn lock(
        &self,
        tx: &mut Transaction<'_, Pg>,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<(AuthorizationState, FreshSessionAuthorization, Deadline)> {
        configuration::lock(tx, &self.client, true).await?;
        self.lock_after_client(tx, proof).await
    }
    /// Caller holds the current enabled client and any required native policy
    /// before acquiring source/owner/session/consent locks in this shared tail.
    pub(super) async fn lock_after_client(
        &self,
        tx: &mut Transaction<'_, Pg>,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<(AuthorizationState, FreshSessionAuthorization, Deadline)> {
        let caller = self.owner.lock(tx).await?;
        let locked = state::lock_pending(tx, proof, &self.client, &caller).await?;
        if locked != self.original {
            return Err(Error::Unauthorized);
        }
        let deadline = Deadline::proof(caller.deadline.expires_us())
            .with_proof(self.original.expires_at_us)
            .with_proof(self.original.session_cap_us)
            .with_proof(locked.expires_at_us)
            .with_proof(locked.session_cap_us);
        Ok((locked, caller, deadline))
    }
    pub(super) fn destination(
        &self,
        mut state: AuthorizationState,
        expiry: i64,
    ) -> Result<IssuerAuthorizationDestination> {
        Ok(IssuerAuthorizationDestination {
            client: self.client.clone(),
            redirect_uri: state.redirect_uri,
            state: state.state.take().ok_or(Error::Unavailable)?,
            expires_at_us: expiry,
        })
    }
}
