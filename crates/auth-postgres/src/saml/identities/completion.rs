use super::super::identity_policy;
use super::{ownership, replay, session};
use crate::{Postgres, audit, deadlines::Deadline, unavailable};
use async_trait::async_trait;
use auth_core::{AuditEvent, Result, SamlIdentityRepository, SamlMappedIdentity, User, Verifier};

#[async_trait]
impl SamlIdentityRepository for Postgres {
    async fn finish_saml_identity(
        &self,
        mapped: SamlMappedIdentity,
        bearer: Verifier,
    ) -> Result<User> {
        let proof = mapped.assertion();
        let reg = proof.registration();
        // Bounded expired-metadata housekeeping finishes before the authority
        // transaction: it holds no source, subject or owner lock.
        replay::prune(&self.pool, reg).await?;
        let mut tx = self.pool.begin().await.map_err(unavailable)?;
        identity_policy::lock(&mut tx, mapped.policy()).await?;
        let deadline = Deadline::proof(proof.expires_at_us());
        deadline.check(&mut tx).await?;
        replay::reserve(&mut tx, proof).await?;
        let (user, identity) = ownership::resolve(&mut tx, &mapped).await?;
        let session_id = session::create(&mut tx, &mapped, user.id, identity, bearer).await?;
        audit::record(
            &mut tx,
            user.realm_id,
            AuditEvent::SamlAuthenticated {
                user_id: user.id,
                session_id,
            },
        )
        .await?;
        // Last statement after all potentially blocking writes, before commit.
        deadline.check(&mut tx).await?;
        tx.commit().await.map_err(unavailable)?;
        Ok(user)
    }
}
