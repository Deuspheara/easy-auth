mod admission;
mod deletion;
mod email_attachment;
mod email_change;
mod erasure;
#[cfg(feature = "oidc-identities")]
pub(crate) mod provider_deletion;

use crate::{Postgres, unavailable};
use auth_core::{Error, Result, Verifier};
use uuid::Uuid;

impl Postgres {
    pub(super) async fn current_email(&self, realm: Uuid, current: Verifier) -> Result<String> {
        sqlx::query_scalar(
            r#"
            SELECT u.email
            FROM auth_users u
            JOIN auth_sessions s ON s.realm_id=u.realm_id
            AND s.user_id=u.id
            WHERE s.realm_id=$1
            AND s.token_hash=$2
            AND u.email IS NOT NULL AND u.authentication_policy='mailbox'
            "#,
        )
        .bind(realm)
        .bind(current.as_slice())
        .fetch_optional(&self.pool)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)
    }
}

#[cfg(feature = "saml-identities")]
mod saml_deletion;
