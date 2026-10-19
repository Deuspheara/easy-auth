use crate::unavailable;
use auth_core::{Error, PasskeyManagementRequest, Result};
use sqlx::Transaction;
use uuid::Uuid;

pub(super) async fn caller(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    request: &PasskeyManagementRequest,
) -> Result<super::super::authority::Caller> {
    super::super::authority::fresh_passkey_caller(tx, request.realm, request.session).await
}

pub(super) async fn lock_key(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    request: &PasskeyManagementRequest,
    user: Uuid,
    id: Uuid,
    version: Uuid,
) -> Result<()> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM auth_passkeys WHERE realm_id=$1 AND user_id=$2 AND rp_id=$3 AND id=$4 AND management_version=$5 FOR UPDATE",
    ).bind(request.realm).bind(user).bind(&request.rp_id).bind(id).bind(version)
        .fetch_optional(&mut **tx).await.map_err(unavailable)?.ok_or(Error::Unauthorized)?;
    Ok(())
}
