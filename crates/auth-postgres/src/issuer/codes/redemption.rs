use super::{
    clock,
    state::{self, AuthorizationState},
};
use crate::{
    Postgres, audit, deadlines::Deadline, issuer::authentication, sessions::FreshSessionSnapshot,
    unavailable,
};
use auth_core::{
    AuditEvent, Error, IssuerCodeRedemption, IssuerGrantData, IssuerTokenError, IssuerTokenResult,
    Result, Verifier,
};

struct CodeCandidate {
    original: AuthorizationState,
    owner: FreshSessionSnapshot,
}
impl CodeCandidate {
    async fn read(store: &Postgres, request: &IssuerCodeRedemption<'_>) -> Result<Option<Self>> {
        let Some(original) = state::code(store, request).await? else {
            return Ok(None);
        };
        let token: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT token_hash FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3",
        )
        .bind(request.authority.realm())
        .bind(original.user_id)
        .bind(original.session_id)
        .fetch_optional(&store.pool)
        .await
        .map_err(unavailable)?;
        let Some(token) = token else {
            return Ok(None);
        };
        let token: Verifier = token.try_into().map_err(|_| Error::Unavailable)?;
        let owner =
            match FreshSessionSnapshot::load(&store.pool, request.authority.realm(), token).await {
                Ok(owner) => owner,
                Err(Error::Unauthorized) => return Ok(None),
                Err(error) => return Err(error),
            };
        Ok(Some(Self { original, owner }))
    }
}
pub(super) async fn redeem(
    store: &Postgres,
    request: &IssuerCodeRedemption<'_>,
) -> IssuerTokenResult<IssuerGrantData> {
    // These reads only choose lock order. Even a missing/expired candidate must
    // not skip actual registered client authentication before invalid_grant.
    let candidate = CodeCandidate::read(store, request).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    // Authenticate before classifying even a malformed/mismatched redirect.
    // Exact original URI equality is checked again under the code row lock.
    if !request.client.permits_redirect(request.redirect_uri) {
        return Err(IssuerTokenError::InvalidGrant);
    }
    let candidate = candidate.ok_or(IssuerTokenError::InvalidGrant)?;
    let caller = candidate.owner.lock(&mut tx).await?;
    let mut locked = state::lock_code(&mut tx, request, &caller).await?;
    if locked != candidate.original {
        return Err(IssuerTokenError::InvalidGrant);
    }
    let code_expiry = locked
        .code_expires_at_us
        .ok_or(IssuerTokenError::Unavailable)?;
    let deadline = Deadline::proof(caller.deadline.expires_us())
        .with_proof(code_expiry)
        .with_proof(locked.session_cap_us)
        .with_proof(
            candidate
                .original
                .code_expires_at_us
                .ok_or(IssuerTokenError::Unavailable)?,
        )
        .with_proof(candidate.original.session_cap_us);
    let nonce = locked.nonce.take().ok_or(IssuerTokenError::Unavailable)?;
    let subject = locked.subject.ok_or(IssuerTokenError::Unavailable)?;
    let now = clock::now(&mut tx).await?;
    if now >= deadline.expires_us() {
        return Err(IssuerTokenError::InvalidGrant);
    }
    sqlx::query(
        r#"
            UPDATE auth_issuer_authorizations
            SET status='consumed',consumed_at_us=$3,state=NULL,nonce=NULL,pkce_challenge=NULL
            WHERE realm_id=$1
            AND id=$2
            AND status='approved'
        "#,
    )
    .bind(request.authority.realm())
    .bind(locked.id)
    .bind(now)
    .execute(&mut *tx)
    .await
    .map_err(unavailable)?;
    audit::record(
        &mut tx,
        request.authority.realm(),
        AuditEvent::IssuerCodeRedeemed {
            user_id: caller.user,
            actor_session_id: caller.session,
            client_id: request.client.client(),
            authorization_id: locked.id,
        },
    )
    .await?;
    let issued_at_us = clock::now(&mut tx).await?;
    deadline.check(&mut tx).await?;
    tx.commit().await.map_err(unavailable)?;
    Ok(IssuerGrantData {
        authorization: locked.id,
        owner: caller.user,
        session: caller.session,
        subject,
        nonce,
        authentication_method: caller.method,
        authenticated_at_us: caller.authenticated_at_us,
        issued_at_us,
        expires_at_us: deadline.expires_us(),
        session_expires_at_us: locked.session_cap_us,
    })
}
