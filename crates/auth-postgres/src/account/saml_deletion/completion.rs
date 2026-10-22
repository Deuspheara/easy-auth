use super::bound_owner;
use crate::{
    Postgres,
    deadlines::Deadline,
    saml::{identity_policy, replay},
    unavailable,
};
use async_trait::async_trait;
use auth_core::{Error, Result, SamlAccountDeletionRepository, SamlVerifiedDeletion};

#[async_trait]
impl SamlAccountDeletionRepository for Postgres {
    async fn finish_saml_account_deletion(&self, input: SamlVerifiedDeletion) -> Result<()> {
        let proof = input.assertion();
        let reg = proof.registration();
        replay::prune(&self.pool, reg).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        identity_policy::lock(&mut tx, input.policy()).await?;
        let proof_deadline = Deadline::proof(proof.expires_at_us())
            .with_proof(proof.session_expires_at_us())
            .with_proof(input.fresh_until_us());
        proof_deadline.check(&mut tx).await?;
        // Keep the same stable replay-before-owner order as SAML sign-in. No
        // signature operation or network call occurs under these SQL locks.
        replay::reserve(&mut tx, proof).await?;
        let owner = bound_owner::lock(&mut tx, reg, input.binding()).await?;
        let same_subject: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_saml_identities WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND subject=$4)")
            .bind(reg.realm())
            .bind(owner.binding.identity)
            .bind(owner.binding.user)
            .bind(proof.subject())
            .fetch_one(&mut *tx)
            .await
            .map_err(unavailable)?;
        let (not_future, observed_at_us): (bool, i64) = sqlx::query_as(
            "WITH observed AS MATERIALIZED (SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint AS now_us) SELECT now_us >= $1,now_us FROM observed",
        )
        .bind(proof.authenticated_at_us())
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        if !same_subject || !not_future {
            return Err(Error::Unauthorized);
        }
        input.validate_authentication_at(observed_at_us)?;
        let deadline = owner
            .deadline
            .with_proof(proof.expires_at_us())
            .with_proof(proof.session_expires_at_us())
            .with_proof(input.fresh_until_us());
        deadline.check(&mut tx).await?;
        super::super::erasure::erase(
            &mut tx,
            reg.realm(),
            owner.binding.user,
            owner.email.as_deref(),
        )
        .await?;
        // Original request/session and all signed caps remain valid after erasure
        // removes the authorizing rows and after every audit/FK/notice wait.
        deadline.check(&mut tx).await?;
        tx.commit().await.map_err(unavailable)
    }
}
