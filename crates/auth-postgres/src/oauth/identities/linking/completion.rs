use super::{super::subject, notices};
use crate::{
    Postgres, audit, oauth::lock_identity_policy, sessions::FreshSessionSnapshot, unavailable,
};
use auth_core::{
    AuditEvent, Error, LinkedProvider, OAuthPurpose, OidcMappedIdentity, ProviderKind, Result,
    Verifier,
};
use uuid::Uuid;

pub(super) async fn finish(
    store: &Postgres,
    mapped: OidcMappedIdentity,
    current: Verifier,
) -> Result<LinkedProvider> {
    let proof = mapped.identity();
    let (owner, expected_session) = match proof.purpose() {
        OAuthPurpose::Link { user, session } => (*user, *session),
        _ => return Err(Error::Unauthorized),
    };
    if owner.is_nil() || current != expected_session {
        return Err(Error::Unauthorized);
    }
    let c = proof.configuration();
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    lock_identity_policy(&mut tx, mapped.policy()).await?;
    subject::lock(
        &mut tx,
        c.realm(),
        c.connection(),
        c.client(),
        c.issuer(),
        proof.subject(),
    )
    .await?;
    subject::reject_deleted(&mut tx, &mapped).await?;
    let snapshot = FreshSessionSnapshot::load(&mut *tx, c.realm(), current).await?;
    let caller = snapshot.lock(&mut tx).await?;
    if caller.user != owner {
        return Err(Error::Unauthorized);
    }
    let deadline = caller.deadline.with_proof(proof.expires_us());
    deadline.check(&mut tx).await?;
    let exists:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM auth_oidc_identities WHERE realm_id=$1 AND connection_id=$2 AND client_id=$3 AND issuer=$4 AND subject=$5)")
        .bind(c.realm()).bind(c.connection()).bind(c.client()).bind(c.issuer()).bind(proof.subject()).fetch_one(&mut *tx).await.map_err(unavailable)?;
    // No ownership transfer or owner/email enumeration, including same-owner retries.
    if exists {
        return Err(Error::Unauthorized);
    }
    let identity = Uuid::new_v4();
    sqlx::query("INSERT INTO auth_oidc_identities(realm_id,id,connection_id,client_id,issuer,subject,user_id,explicitly_linked) VALUES($1,$2,$3,$4,$5,$6,$7,true)")
        .bind(c.realm()).bind(identity).bind(c.connection()).bind(c.client()).bind(c.issuer()).bind(proof.subject()).bind(owner).execute(&mut *tx).await.map_err(unavailable)?;
    audit::record(
        &mut tx,
        c.realm(),
        AuditEvent::OidcIdentityLinked {
            user_id: owner,
            actor_session_id: caller.session,
            identity_id: identity,
        },
    )
    .await?;
    notices::enqueue(&mut tx, c.realm(), owner).await?;
    // No table/write wait follows this original proof/fresh-session cap.
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(LinkedProvider {
        id: identity,
        kind: ProviderKind::Oidc,
        issuer: c.issuer().to_owned(),
    })
}
