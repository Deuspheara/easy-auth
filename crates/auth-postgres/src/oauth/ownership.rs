use crate::{deadlines::Deadline, locking::fresh_session, unavailable};
use auth_core::{Error, OAuthConnection, OAuthPurpose, Result};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) struct Owner {
    pub(super) purpose: &'static str,
    pub(super) user: Option<Uuid>,
    pub(super) session: Option<Uuid>,
    pub(super) deadline: Option<Deadline>,
}

pub(super) async fn lock(
    tx: &mut Transaction<'_, Postgres>,
    configuration: &OAuthConnection,
    purpose: &OAuthPurpose,
) -> Result<Owner> {
    let realm = configuration.realm();
    match purpose {
        OAuthPurpose::SignIn => Ok(Owner {
            purpose: "sign_in",
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
                purpose: "link",
                user: Some(*user),
                session: Some(session),
                deadline: Some(deadline),
            })
        }
        OAuthPurpose::DeleteProviderAccount { user, session } => {
            #[cfg(feature = "oidc-identities")]
            {
                let owner =
                    crate::account::provider_deletion::lock(tx, configuration, *user, *session)
                        .await?;
                Ok(Owner {
                    purpose: "delete_provider_account",
                    user: Some(owner.user),
                    session: Some(owner.session),
                    deadline: Some(owner.deadline),
                })
            }
            #[cfg(not(feature = "oidc-identities"))]
            {
                let _ = (user, session);
                Err(Error::Unauthorized)
            }
        }
    }
}
