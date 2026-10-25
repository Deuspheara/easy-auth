use super::decision_state::DecisionCandidate;
use crate::{Postgres, unavailable};
use auth_core::{IssuerAuthorizationDestination, IssuerConsentProof, Result, Verifier};

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
    let (_approved_at, expiry) = super::approval::approve(
        &mut tx,
        proof,
        code,
        &candidate.client,
        &state,
        &caller,
        &deadline,
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
