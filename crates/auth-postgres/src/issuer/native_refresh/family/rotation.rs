use super::{
    revocation,
    state::{Family, Refresh},
    writing,
};
use crate::{
    Postgres,
    issuer::{authentication, native_refresh::policy, signing},
    sessions::DelegatedSessionSnapshot,
    unavailable,
};
use auth_core::{
    ISSUER_NATIVE_ACCESS_LIFETIME_SECONDS, IssuerNativeCredentialAction as Action,
    IssuerNativeCredentialKind as Kind, IssuerNativeRefreshData,
    IssuerNativeRefreshOutcome as Outcome, IssuerNativeRotationRequest, IssuerTokenError,
    IssuerTokenResult, MAX_ISSUER_NATIVE_REFRESH_GENERATION,
};

const MIN_TOKEN_REMAINING_US: i64 = 1_000_000;

pub(super) async fn rotate(
    store: &Postgres,
    request: &IssuerNativeRotationRequest<'_>,
) -> IssuerTokenResult<Outcome> {
    let credential = &request.credential;
    credential.validate_client()?;
    let candidate = Family::refresh(store, credential).await?;
    // Read only to choose the later source/owner lock path. Reduction paths do
    // not require a live source; active rotation must revalidate this snapshot.
    let owner_snapshot = match candidate.as_ref() {
        Some(family) => Some(
            DelegatedSessionSnapshot::load(
                &store.pool,
                family.origin.realm_id,
                family.origin.user_id,
                family.origin.session_id,
            )
            .await,
        ),
        None => None,
    };

    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, credential.client, credential.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    let Some(snapshot) = candidate else {
        return Ok(Outcome::InvalidGrant);
    };
    let Some(presented) = Refresh::read(&mut tx, credential, snapshot.origin.id).await? else {
        return Ok(Outcome::InvalidGrant);
    };
    // Current client serialization permits a fresh spent-state decision before
    // source locks. Reuse/limit cleanup reduces authority without requiring a
    // live provider source, cookie freshness or a fake owner-session actor.
    if presented.spent_at_us.is_some()
        || presented.generation >= MAX_ISSUER_NATIVE_REFRESH_GENERATION
    {
        if !revocation::lock_owner(&mut tx, &snapshot).await? {
            return Ok(Outcome::InvalidGrant);
        }
        let Some(family) = snapshot.lock(&mut tx).await? else {
            return Ok(Outcome::InvalidGrant);
        };
        let Some(presented) = Refresh::lock(&mut tx, credential, family.origin.id).await? else {
            return Ok(Outcome::InvalidGrant);
        };
        let reuse = presented.spent_at_us.is_some();
        if family.revoked_at_us.is_none()
            && (reuse || presented.generation >= MAX_ISSUER_NATIVE_REFRESH_GENERATION)
        {
            revocation::reduce(
                &mut tx,
                &family,
                presented.generation,
                Kind::RefreshToken,
                if reuse {
                    Action::ReuseRevoked
                } else {
                    Action::Revoked
                },
            )
            .await?;
        }
        tx.commit().await.map_err(unavailable)?;
        return Ok(if reuse {
            Outcome::ReuseRevoked
        } else {
            Outcome::InvalidGrant
        });
    }
    let saved_policy = snapshot.policy(credential.authority, credential.client)?;
    policy::lock(&mut tx, &saved_policy, true).await?;
    let key = signing::lock_current(&mut tx, credential.authority).await?;
    let owner = owner_snapshot.ok_or(IssuerTokenError::InvalidGrant)??;
    owner
        .lock(
            &mut tx,
            &saved_policy,
            &snapshot.origin.authentication_method,
            snapshot.origin.authenticated_at_us,
            snapshot.origin.expires_at_us,
        )
        .await?;
    let Some(family) = snapshot.lock(&mut tx).await? else {
        return Ok(Outcome::InvalidGrant);
    };
    let Some(presented) = Refresh::lock(&mut tx, credential, family.origin.id).await? else {
        return Ok(Outcome::InvalidGrant);
    };
    if presented.spent_at_us.is_some() {
        revocation::reduce(
            &mut tx,
            &family,
            presented.generation,
            Kind::RefreshToken,
            Action::ReuseRevoked,
        )
        .await?;
        tx.commit().await.map_err(unavailable)?;
        return Ok(Outcome::ReuseRevoked);
    }
    let now = signing::now(&mut tx).await?;
    if family.revoked_at_us.is_some()
        || presented.generation != family.generation
        || now >= family.origin.expires_at_us
        || now >= family.idle_until_us
    {
        return Ok(Outcome::InvalidGrant);
    }
    let idle_until = now
        .checked_add(i64::from(saved_policy.idle_seconds()) * 1_000_000)
        .ok_or(IssuerTokenError::Unavailable)?
        .min(family.origin.expires_at_us);
    let access_expiry = now
        .checked_add(ISSUER_NATIVE_ACCESS_LIFETIME_SECONDS * 1_000_000)
        .ok_or(IssuerTokenError::Unavailable)?
        .min(idle_until)
        .min(key.publication().sign_until_us())
        .min(key.publication().verify_until_us());
    let generation = writing::rotate(
        &mut tx,
        request,
        &family,
        &key,
        now,
        access_expiry,
        idle_until,
    )
    .await?;
    let final_now = signing::now(&mut tx).await?;
    if final_now >= key.publication().sign_until_us() {
        return Err(IssuerTokenError::Unavailable);
    }
    if final_now >= family.origin.expires_at_us
        || final_now >= family.idle_until_us
        || access_expiry.saturating_sub(final_now) < MIN_TOKEN_REMAINING_US
        || idle_until.saturating_sub(final_now) < MIN_TOKEN_REMAINING_US
    {
        return Err(IssuerTokenError::InvalidGrant);
    }
    tx.commit().await.map_err(unavailable)?;
    Ok(Outcome::Rotated(Box::new(IssuerNativeRefreshData {
        policy: saved_policy,
        family_id: family.origin.id,
        subject: family.origin.subject,
        generation,
        prepared_at_us: family.origin.prepared_at_us,
        source_absolute_cap_us: family.origin.source_absolute_cap_us,
        family_expires_at_us: family.origin.expires_at_us,
        issued_at_us: now,
        access_expires_at_us: access_expiry,
        refresh_expires_at_us: idle_until,
        checked_at_us: final_now,
    })))
}
