use super::{ProbeResult, errors, observations};
use auth_core::{
    AuthenticationPolicy, Error, GoogleAuthorizationCompletion, OidcIdentityPolicy, OidcSignIn,
    Repository, Secret, User,
};
use auth_postgres::Postgres;
use serde_json::{Value, json};
use sqlx::PgPool;
use std::sync::Arc;

pub(super) async fn commit(
    pool: &PgPool,
    store: &Arc<Postgres>,
    policy: &OidcIdentityPolicy,
    completion: GoogleAuthorizationCompletion,
) -> ProbeResult<Value> {
    let identity = match completion {
        GoogleAuthorizationCompletion::Verified(identity) => identity,
        GoogleAuthorizationCompletion::Denied => return Err("provider_denied"),
        GoogleAuthorizationCompletion::ProviderFailure => return Err("provider_failure"),
    };
    let auth_time_present = identity.authenticated_at().is_some();
    let mapped = policy.map(*identity).map_err(errors::local)?;
    let (owner, session) = OidcSignIn::new(store.clone())
        .finish(mapped)
        .await
        .map_err(errors::local)?;
    if owner.email.is_some()
        || owner.authentication_policy != AuthenticationPolicy::ProviderRequired
    {
        return Err("unexpected_local_policy");
    }
    validate_and_revoke(store, &owner, &session).await?;
    let mut report = json!({"status":"passed","scope":"manual_registered_native_signin","signature_verified":true,
        "local_session_committed":true,"local_session_validated":true,"local_session_revoked":true,
        "signed_auth_time_present":auth_time_present,"freshness_or_deletion_accepted":false});
    let facts = observations::read(pool, owner.realm_id).await?;
    if facts != (1, 1, 1, 2, 0, 1) {
        return Err("unexpected_local_authority_facts");
    }
    report["facts"] = json!({"users":facts.0,"identities":facts.1,"sessions":facts.2,
        "audits":facts.3,"pending":facts.4,"revoked_sessions":facts.5});
    Ok(report)
}

async fn validate_and_revoke(
    store: &Arc<Postgres>,
    owner: &User,
    session: &Secret,
) -> ProbeResult<()> {
    let authenticated = store
        .authenticate(owner.realm_id, session.verifier())
        .await
        .map_err(errors::local)?;
    if authenticated != *owner {
        return Err("local_session_owner");
    }
    store
        .revoke(owner.realm_id, session.verifier())
        .await
        .map_err(errors::local)?;
    match store.authenticate(owner.realm_id, session.verifier()).await {
        Err(Error::Unauthorized) => {}
        Err(error) => return Err(errors::local(error)),
        Ok(_) => return Err("revoked_session_still_active"),
    }
    Ok(())
}
