use crate::{Postgres, oauth::lock_identity_policy, unavailable};
use async_trait::async_trait;
use auth_core::{
    Error, MAX_OIDC_DELETION_AUTH_AGE_SECONDS, OAuthPurpose, OidcAccountDeletionRepository,
    OidcMappedIdentity, Result,
};

#[async_trait]
impl OidcAccountDeletionRepository for Postgres {
    async fn finish_oidc_account_deletion(&self, mapped: OidcMappedIdentity) -> Result<()> {
        let proof = mapped.identity();
        let OAuthPurpose::DeleteProviderAccount { user, session } = proof.purpose() else {
            return Err(Error::Unauthorized);
        };
        let authenticated = proof.authenticated_at().ok_or(Error::Unauthorized)?;
        let authenticated_us = i64::try_from(i128::from(authenticated) * 1_000_000)
            .map_err(|_| Error::Unauthorized)?;
        let freshness_cap = i64::try_from(
            (i128::from(authenticated) + i128::from(MAX_OIDC_DELETION_AUTH_AGE_SECONDS))
                * 1_000_000,
        )
        .map_err(|_| Error::Unauthorized)?;
        let c = proof.configuration();
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        // The shared complete-policy guard locks configuration then policy.
        // No provider network operation or signature check occurs under locks.
        lock_identity_policy(&mut tx, mapped.policy()).await?;
        let owner = super::authorization::lock(&mut tx, c, *user, *session).await?;
        let same_subject: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_oidc_identities WHERE realm_id=$1 AND id=$2 AND user_id=$3 AND subject=$4)")
            .bind(c.realm()).bind(owner.identity).bind(owner.user).bind(proof.subject())
            .fetch_one(&mut *tx).await.map_err(unavailable)?;
        let not_future: bool = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint >= $1",
        )
        .bind(authenticated_us)
        .fetch_one(&mut *tx)
        .await
        .map_err(unavailable)?;
        if !same_subject || !not_future {
            return Err(Error::Unauthorized);
        }
        let deadline = owner
            .deadline
            .with_proof(proof.expires_us())
            .with_proof(freshness_cap);
        deadline.check(&mut tx).await?;
        // User deletion erases sessions/proofs; retain their locked original caps
        // for the final check after all audit/notice/FK/uniqueness waits.
        super::super::erasure::erase(&mut tx, c.realm(), owner.user, owner.email.as_deref())
            .await?;
        deadline.check(&mut tx).await?;
        tx.commit().await.map_err(unavailable)
    }
}
