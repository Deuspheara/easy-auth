use crate::{deadlines::Deadline, unavailable};
use auth_core::{Error, PasskeyManagementRequest, Result};
use sqlx::Transaction;
use uuid::Uuid;

pub(super) struct Caller {
    pub(super) user: Uuid,
    pub(super) session: Uuid,
    pub(super) deadline: Deadline,
}

pub(super) async fn caller(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    request: &PasskeyManagementRequest,
) -> Result<Caller> {
    let (user, session, _) =
        super::super::policy::fresh_owner(tx, request.realm, request.session).await?;
    let passkey: bool = sqlx::query_scalar(
        "SELECT authentication_method='passkey' FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3",
    ).bind(request.realm).bind(user).bind(session)
        .fetch_one(&mut **tx).await.map_err(unavailable)?;
    if !passkey {
        return Err(Error::Unauthorized);
    }
    let deadline = Deadline::fresh_session(tx, request.realm, user, session).await?;
    Ok(Caller {
        user,
        session,
        deadline,
    })
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
