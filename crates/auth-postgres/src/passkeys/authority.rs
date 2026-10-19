use crate::{deadlines::Deadline, unavailable};
use auth_core::{Error, Result, Verifier};
use sqlx::Transaction;
use uuid::Uuid;

pub(super) struct Caller {
    pub(super) user: Uuid,
    pub(super) session: Uuid,
    pub(super) deadline: Deadline,
}

pub(super) async fn fresh_passkey_caller(
    tx: &mut Transaction<'_, sqlx::Postgres>,
    realm: Uuid,
    current: Verifier,
) -> Result<Caller> {
    let (user, session, _) = super::policy::fresh_owner(tx, realm, current).await?;
    let passkey: bool = sqlx::query_scalar(
        "SELECT authentication_method='passkey' FROM auth_sessions WHERE realm_id=$1 AND user_id=$2 AND id=$3",
    ).bind(realm).bind(user).bind(session)
        .fetch_one(&mut **tx).await.map_err(unavailable)?;
    if !passkey {
        return Err(Error::Unauthorized);
    }
    let deadline = Deadline::fresh_session(tx, realm, user, session).await?;
    Ok(Caller {
        user,
        session,
        deadline,
    })
}
