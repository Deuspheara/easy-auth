use super::super::{approval, decision_state::DecisionCandidate, state};
use super::{preparation, state::ConsentState};
use crate::{
    Postgres,
    issuer::{configuration, native_refresh::policy},
    sessions::FreshSessionSnapshot,
    unavailable,
};
use auth_core::{
    Error, IssuerAuthorizationDestination, IssuerConsentProof,
    IssuerNativeAuthorizationDestination, IssuerNativeConsentData, IssuerRedirectProfile, Result,
    Verifier,
};

struct NativeCandidate {
    base: DecisionCandidate,
    consent: ConsentState,
}
impl NativeCandidate {
    async fn load(store: &Postgres, proof: &IssuerConsentProof<'_>) -> Result<Self> {
        let original = state::pending(store, proof).await?;
        let client = store
            .load_issuer_client(proof.authority.realm(), original.client_id)
            .await?;
        if !original.native_refresh
            || client.redirect_profile() != IssuerRedirectProfile::NativeRefreshLoopback
            || client.revision() != original.client_revision
        {
            return Err(Error::Unauthorized);
        }
        let consent = ConsentState::load(store, &original).await?;
        let owner =
            FreshSessionSnapshot::load(&store.pool, proof.authority.realm(), proof.current).await?;
        Ok(Self {
            base: DecisionCandidate {
                original,
                client,
                owner,
            },
            consent,
        })
    }
    fn data(&self, proof: &IssuerConsentProof<'_>) -> Result<IssuerNativeConsentData> {
        self.consent.data(proof.authority, &self.base.client)
    }
}
pub(super) async fn preview(
    store: &Postgres,
    proof: &IssuerConsentProof<'_>,
) -> Result<IssuerNativeAuthorizationDestination> {
    let candidate = NativeCandidate::load(store, proof).await?;
    let data = candidate.data(proof)?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    configuration::lock(&mut tx, &candidate.base.client, true).await?;
    policy::lock(&mut tx, &data.policy, true).await?;
    let (state, caller, deadline) = candidate.base.lock_after_client(&mut tx, proof).await?;
    candidate.consent.lock(&mut tx, &state).await?;
    if data.grant_expires_at_us
        > preparation::absolute_cap(&mut tx, proof.authority, &caller).await?
    {
        return Err(Error::Unauthorized);
    }
    deadline
        .with_proof(data.grant_expires_at_us)
        .check(&mut tx)
        .await?;
    tx.commit().await.map_err(unavailable)?;
    let expiry = state.expires_at_us;
    Ok(IssuerNativeAuthorizationDestination {
        destination: candidate.base.destination(state, expiry)?,
        consent: data,
    })
}
pub(super) async fn approve(
    store: &Postgres,
    proof: &IssuerConsentProof<'_>,
    code: Verifier,
) -> Result<IssuerNativeAuthorizationDestination> {
    let candidate = NativeCandidate::load(store, proof).await?;
    let mut data = candidate.data(proof)?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    configuration::lock(&mut tx, &candidate.base.client, true).await?;
    policy::lock(&mut tx, &data.policy, true).await?;
    let (state, caller, deadline) = candidate.base.lock_after_client(&mut tx, proof).await?;
    candidate.consent.lock(&mut tx, &state).await?;
    if data.grant_expires_at_us
        > preparation::absolute_cap(&mut tx, proof.authority, &caller).await?
    {
        return Err(Error::Unauthorized);
    }
    let deadline = deadline.with_proof(data.grant_expires_at_us);
    let (at, expiry) = approval::approve(
        &mut tx,
        proof,
        code,
        &candidate.base.client,
        &state,
        &caller,
        &deadline,
    )
    .await?;
    candidate.consent.approve(&mut tx, at).await?;
    deadline.with_proof(expiry).check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    data.approved_at_us = Some(at);
    Ok(IssuerNativeAuthorizationDestination {
        destination: candidate.base.destination(state, expiry)?,
        consent: data,
    })
}
pub(super) async fn cancel(
    store: &Postgres,
    proof: &IssuerConsentProof<'_>,
) -> Result<IssuerAuthorizationDestination> {
    let candidate = NativeCandidate::load(store, proof).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    // Reduces only the bound pending operation. Operator policy disable cannot
    // prevent cleanup; no current policy is needed to cancel existing consent.
    configuration::lock(&mut tx, &candidate.base.client, true).await?;
    let (state, _caller, deadline) = candidate.base.lock_after_client(&mut tx, proof).await?;
    candidate.consent.lock(&mut tx, &state).await?;
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
    candidate.base.destination(state, expiry)
}
