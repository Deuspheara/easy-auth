use crate::{
    Postgres,
    issuer::{
        authentication, codes::native::redemption::NativeCodeCandidate, native_refresh::policy,
        signing,
    },
    unavailable,
};
use auth_core::{
    IssuerCodeRedemption, IssuerNativeTokenPreparationData, IssuerRedirectProfile,
    IssuerTokenError, IssuerTokenPreparationData, IssuerTokenResult,
};

pub(super) async fn prepare(
    store: &Postgres,
    request: &IssuerCodeRedemption<'_>,
) -> IssuerTokenResult<IssuerNativeTokenPreparationData> {
    if request.authority.realm() != request.client.realm()
        || request.client.redirect_profile() != IssuerRedirectProfile::NativeRefreshLoopback
    {
        return Err(IssuerTokenError::InvalidClient);
    }
    let candidate = NativeCodeCandidate::read(store, request).await?;
    let mut tx = store.pool.begin().await.map_err(unavailable)?;
    authentication::validate_current(&mut tx, request.client, request.authentication)
        .await
        .map_err(IssuerTokenError::client)?;
    let candidate = candidate.ok_or(IssuerTokenError::InvalidGrant)?;
    policy::lock(&mut tx, &candidate.consent().policy, true).await?;
    // Client -> policy -> keys -> source/owner/fresh session -> code -> sidecar.
    let signing = signing::lock_current(&mut tx, request.authority).await?;
    let locked = candidate.lock(&mut tx, request).await?;
    let (code_snapshot, consent_snapshot) = locked.snapshots(&mut tx, request).await?;
    let now = signing::now(&mut tx).await?;
    if now >= locked.expires_at_us() {
        return Err(IssuerTokenError::InvalidGrant);
    }
    if now >= signing.publication().sign_until_us() {
        return Err(IssuerTokenError::Unavailable);
    }
    locked.quota(&mut tx, request, now).await?;
    let grant = locked.facts(now)?;
    let consent = locked.consent_data(request)?;
    let consent_authorization = grant.authorization;
    tx.commit().await.map_err(unavailable)?;
    Ok(IssuerNativeTokenPreparationData {
        token: IssuerTokenPreparationData {
            signing,
            grant,
            code_snapshot,
        },
        consent,
        consent_authorization,
        consent_snapshot,
    })
}
