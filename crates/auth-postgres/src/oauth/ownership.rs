use crate::{deadlines::Deadline, locking::fresh_session, unavailable};
use auth_core::{Error, OAuthPurpose, Result};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) struct Owner {
    pub(super) user: Option<Uuid>,
    pub(super) session: Option<Uuid>,
    pub(super) deadline: Option<Deadline>,
}

pub(super) async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    realm: Uuid,
    purpose: &OAuthPurpose,
) -> Result<Owner> {
    match purpose {
        OAuthPurpose::SignIn => Ok(Owner {
            user: None,
            session: None,
            deadline: None,
        }),
        OAuthPurpose::Link { user, session } => {
            // No email mutation here and no email lock acquired afterward.
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM auth_users WHERE realm_id=$1 AND id=$2 FOR UPDATE",
            )
            .bind(realm)
            .bind(user)
            .fetch_optional(&mut **tx)
            .await
            .map_err(unavailable)?
            .ok_or(Error::Unauthorized)?;
            let session = fresh_session(tx, realm, *user, *session).await?;
            let deadline = Deadline::fresh_session(tx, realm, *user, session).await?;
            Ok(Owner {
                user: Some(*user),
                session: Some(session),
                deadline: Some(deadline),
            })
        }
    }
}
