use super::super::identity_policy;
use super::ownership;
use crate::{Postgres, audit, deadlines::Deadline, unavailable};
use async_trait::async_trait;
use auth_core::{
    AuditEvent, Error, OAuthPurpose, OidcIdentityRepository, OidcMappedIdentity, Result, User,
    Verifier,
};
use uuid::Uuid;

#[async_trait]
impl OidcIdentityRepository for Postgres {
    async fn finish_oidc_identity(
        &self,
        mapped: OidcMappedIdentity,
        session: Verifier,
    ) -> Result<User> {
        finish(
            self,
            mapped,
            session,
            #[cfg(feature = "apple-grants")]
            None,
        )
        .await
    }
}

pub(super) async fn finish(
    store: &Postgres,
    mapped: OidcMappedIdentity,
    session: Verifier,
    #[cfg(feature = "apple-grants")] capture: Option<auth_core::AppleGrantCapture>,
) -> Result<User> {
    let proof = mapped.identity();
    if !matches!(proof.purpose(), OAuthPurpose::SignIn) {
        return Err(Error::Unauthorized);
    }
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    identity_policy::lock(&mut tx, mapped.policy()).await?;
    let deadline = Deadline::proof(proof.expires_us());
    deadline.check(&mut tx).await?;
    let (user, identity) = ownership::resolve(&mut tx, &mapped).await?;
    #[cfg(feature = "apple-grants")]
    if let Some(capture) = capture {
        super::apple::insert(store, &mut tx, identity, capture).await?;
    }
    let authenticated_at = proof
        .authenticated_at()
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Error::Unauthorized)?;
    let id = Uuid::new_v4();
    sqlx::query(r#"
        INSERT INTO auth_sessions(realm_id,id,user_id,token_hash,authenticated_at,authentication_method,oidc_identity_id,oidc_revision)
        VALUES ($1,$2,$3,$4,CASE WHEN $5::bigint IS NULL THEN '-infinity'::timestamptz ELSE to_timestamp($5::double precision) END,'oidc',$6,$7)
    "#)
    .bind(user.realm_id)
    .bind(id)
    .bind(user.id)
    .bind(session.as_slice())
    .bind(authenticated_at)
    .bind(identity)
    .bind(proof.configuration().revision())
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    audit::record(
        &mut tx,
        user.realm_id,
        AuditEvent::OidcAuthenticated {
            user_id: user.id,
            session_id: id,
        },
    )
    .await?;
    // No write/row wait follows this original-proof clock cap before commit.
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(user)
}
