use super::super::state::Family;
use super::state::Access;
use crate::{
    Postgres,
    issuer::{
        authentication, configuration,
        native_refresh::{consumer, policy},
        signing,
    },
    sessions::DelegatedSessionSnapshot,
    unavailable,
};
use auth_core::{
    Error, IssuerAccessData, IssuerNativeAccessData, IssuerNativeConsumerPolicy, IssuerTokenError,
    IssuerTokenResult, IssuerTokenStatusRequest, Result,
};
use sqlx::{Postgres as Pg, Transaction};

pub(super) async fn inspect(
    store: &Postgres,
    request: &IssuerTokenStatusRequest<'_>,
) -> IssuerTokenResult<Option<IssuerNativeAccessData>> {
    request.validate_introspection()?;
    // Snapshots choose only client/source lock paths. Do not acquire another pool
    // connection while transaction locks are held, or return before authentication.
    let access = Access::read(store, request).await?;
    let family = match &access {
        Some(a) => a.family(store, request).await?,
        None => None,
    };
    let saved = match &access {
        Some(a) => Some(
            store
                .load_issuer_native_consumer(
                    request.authority,
                    request.client.client(),
                    a.client_id,
                )
                .await,
        ),
        None => None,
    };
    let owner = match &family {
        Some(f) => Some(
            DelegatedSessionSnapshot::load(
                &store.pool,
                f.origin.realm_id,
                f.origin.user_id,
                f.origin.session_id,
            )
            .await,
        ),
        None => None,
    };
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    let audience = access
        .as_ref()
        .map_or(request.client.client(), |a| a.client_id);
    consumer::lock_clients(
        &mut tx,
        request.authority.realm(),
        request.client.client(),
        audience,
    )
    .await?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    // Preserve every storage error after authenticating the consumer, even when
    // another snapshot disappeared or became unauthorized during concurrent erasure.
    let saved = match saved {
        Some(Ok(policy)) => Some(policy),
        Some(Err(Error::Unauthorized)) | None => None,
        Some(Err(error)) => return Err(error.into()),
    };
    let owner = match owner {
        Some(Ok(owner)) => Some(owner),
        Some(Err(Error::Unauthorized)) | None => None,
        Some(Err(error)) => return Err(error.into()),
    };
    let result = async {
        let (Some(access), Some(family), Some(saved), Some(owner)) = (access, family, saved, owner)
        else {
            return Ok(None);
        };
        active(&mut tx, request, access, family, saved, owner).await
    }
    .await;
    match result {
        Ok(data) => {
            tx.commit().await.map_err(unavailable)?;
            Ok(data)
        }
        Err(Error::Unauthorized) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Consumer pair -> exact consumer policy -> native policy -> retained key ->
/// original source/owner/session -> family -> generation -> access -> consumed grant.
/// All authority remains locked through the final database clock and commit.
async fn active(
    tx: &mut Transaction<'_, Pg>,
    request: &IssuerTokenStatusRequest<'_>,
    access: Access,
    snapshot: Family,
    saved: IssuerNativeConsumerPolicy,
    owner: DelegatedSessionSnapshot,
) -> Result<Option<IssuerNativeAccessData>> {
    if saved.consumer() != request.client
        || saved.authority() != request.authority
        || saved.audience().client() != access.client_id
    {
        return Ok(None);
    }
    configuration::lock(tx, saved.audience(), true).await?;
    consumer::lock_policy(tx, &saved, true).await?;
    let native = snapshot.policy(request.authority, saved.audience())?;
    policy::lock(tx, &native, true).await?;
    if !signing::lock_retained_key(
        tx,
        request.authority,
        access.key_id,
        access.issued_at_us,
        access.expires_at_us,
    )
    .await?
    {
        return Ok(None);
    }
    owner
        .lock(
            tx,
            &native,
            &snapshot.origin.authentication_method,
            snapshot.origin.authenticated_at_us,
            snapshot.origin.expires_at_us,
        )
        .await?;
    let Some(family) = snapshot.lock(tx).await? else {
        return Ok(None);
    };
    if !access.lock_generation(tx, request).await?
        || !access.lock(tx, request).await?
        || !access.matches(&family)
    {
        return Ok(None);
    }
    // The immutable full-tuple family/consent FKs preserve original proposal and
    // source caps. Refresh inspection deliberately does not impose code freshness.
    let original:Option<bool>=sqlx::query_scalar("SELECT true FROM auth_issuer_authorizations WHERE realm_id=$1 AND issuer=$2 AND id=$3 AND client_id=$4 AND client_revision=$5 AND user_id=$6 AND session_id=$7 AND subject=$8 AND native_refresh AND status='consumed' AND authentication_method=$9 AND authenticated_at_us=$10 FOR SHARE")
        .bind(request.authority.realm()).bind(request.authority.issuer()).bind(family.origin.authorization_id)
        .bind(family.origin.client_id).bind(family.origin.client_revision).bind(family.origin.user_id).bind(family.origin.session_id).bind(family.origin.subject)
        .bind(&family.origin.authentication_method).bind(family.origin.authenticated_at_us).fetch_optional(&mut **tx).await.map_err(unavailable)?;
    let now = signing::now(tx).await?;
    if original != Some(true)
        || now < access.issued_at_us
        || now >= access.expires_at_us
        || now >= family.idle_until_us
        || now >= family.origin.expires_at_us
    {
        return Ok(None);
    }
    Ok(Some(IssuerNativeAccessData {
        policy: saved,
        access: IssuerAccessData {
            realm: request.authority.realm(),
            issuer: request.authority.issuer().into(),
            client: access.client_id,
            subject: access.subject,
            issued_at_us: access.issued_at_us,
            expires_at_us: access.expires_at_us,
            checked_at_us: now,
        },
    }))
}
