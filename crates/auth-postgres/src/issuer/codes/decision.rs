use super::{
    clock,
    state::{self, AuthorizationState},
};
use crate::{
    Postgres, audit,
    deadlines::Deadline,
    issuer::{configuration, subjects},
    sessions::{FreshSessionAuthorization, FreshSessionSnapshot},
    unavailable,
};
use auth_core::{
    AuditEvent, Error, ISSUER_CODE_LIFETIME_SECONDS, IssuerAuthorizationDestination,
    IssuerClientRegistration, IssuerConsentProof, Result, Verifier,
};
use sqlx::{Postgres as Pg, Transaction};

struct DecisionCandidate {
    original: AuthorizationState,
    client: IssuerClientRegistration,
    owner: FreshSessionSnapshot,
}
impl DecisionCandidate {
    async fn load(store: &Postgres, proof: &IssuerConsentProof<'_>) -> Result<Self> {
        let original = state::pending(store, proof).await?;
        let client = store
            .load_issuer_client(proof.authority.realm(), original.client_id)
            .await?;
        if client.revision() != original.client_revision {
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
    async fn lock(
        &self,
        tx: &mut Transaction<'_, Pg>,
        proof: &IssuerConsentProof<'_>,
    ) -> Result<(AuthorizationState, FreshSessionAuthorization, Deadline)> {
        configuration::lock(tx, &self.client, true).await?;
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
    fn destination(
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
pub(super) async fn preview(
    store: &Postgres,
    proof: &IssuerConsentProof<'_>,
) -> Result<IssuerAuthorizationDestination> {
    let candidate = DecisionCandidate::load(store, proof).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    let (state, _caller, deadline) = candidate.lock(&mut tx, proof).await?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    let expiry = state.expires_at_us;
    candidate.destination(state, expiry)
}
pub(super) async fn approve(
    store: &Postgres,
    proof: &IssuerConsentProof<'_>,
    code: Verifier,
) -> Result<IssuerAuthorizationDestination> {
    let candidate = DecisionCandidate::load(store, proof).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    let (state, caller, deadline) = candidate.lock(&mut tx, proof).await?;
    let now = clock::now(&mut tx).await?;
    let expiry = now
        .checked_add(ISSUER_CODE_LIFETIME_SECONDS * 1_000_000)
        .ok_or(Error::Unavailable)?
        .min(deadline.expires_us());
    if expiry <= now {
        return Err(Error::Unauthorized);
    }
    let subject =
        subjects::allocate_for_locked_client(&mut tx, &candidate.client, caller.user).await?;
    sqlx::query(
        r#"
            UPDATE auth_issuer_authorizations
            SET status='approved',subject=$3,code_hash=$4,approved_at_us=$5,code_expires_at_us=$6
            WHERE realm_id=$1
            AND id=$2
            AND status='pending'
        "#,
    )
    .bind(proof.authority.realm())
    .bind(state.id)
    .bind(subject)
    .bind(code.as_slice())
    .bind(now)
    .bind(expiry)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    audit::record(
        &mut tx,
        proof.authority.realm(),
        AuditEvent::IssuerAuthorized {
            user_id: caller.user,
            actor_session_id: caller.session,
            client_id: candidate.client.client(),
            authorization_id: state.id,
        },
    )
    .await?;
    deadline.with_proof(expiry).check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    candidate.destination(state, expiry)
}
pub(super) async fn cancel(
    store: &Postgres,
    proof: &IssuerConsentProof<'_>,
) -> Result<IssuerAuthorizationDestination> {
    let candidate = DecisionCandidate::load(store, proof).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    let (state, _caller, deadline) = candidate.lock(&mut tx, proof).await?;
    sqlx::query(
        "DELETE FROM auth_issuer_authorizations WHERE realm_id=$1 AND id=$2 AND status='pending'",
    )
    .bind(proof.authority.realm())
    .bind(state.id)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    let expiry = state.expires_at_us;
    candidate.destination(state, expiry)
}
