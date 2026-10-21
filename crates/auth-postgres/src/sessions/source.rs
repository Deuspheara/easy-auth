use crate::{locking::fresh_session, unavailable};
use auth_core::{Error, Result, Verifier};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

pub(super) enum Source {
    Local(String),
    #[cfg(feature = "saml-identities")]
    Saml(super::saml::LockedSource),
    #[cfg(feature = "oidc-identities")]
    Oidc(super::oidc::LockedSource),
}

impl Source {
    pub(super) async fn lock(
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        current: Verifier,
    ) -> Result<Self> {
        // Read only the pre-existing column for local sessions, including upgrade
        // tests before the additive provider-source migration has been applied.
        let method: String = sqlx::query_scalar(
            "SELECT authentication_method FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2",
        )
        .bind(realm)
        .bind(current.as_slice())
        .fetch_optional(&mut **tx)
        .await
        .map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        match method.as_str() {
            "oidc" => {
                #[cfg(feature = "oidc-identities")]
                {
                    Ok(Self::Oidc(
                        super::oidc::LockedSource::lock(tx, realm, current).await?,
                    ))
                }
                #[cfg(not(feature = "oidc-identities"))]
                {
                    Err(Error::Unauthorized)
                }
            }
            "saml" => {
                #[cfg(feature = "saml-identities")]
                {
                    Ok(Self::Saml(
                        super::saml::LockedSource::lock(tx, realm, current).await?,
                    ))
                }
                #[cfg(not(feature = "saml-identities"))]
                {
                    Err(Error::Unauthorized)
                }
            }
            _ => Ok(Self::Local(method)),
        }
    }

    pub(super) fn method(&self) -> &str {
        match self {
            Self::Local(method) => method,
            #[cfg(feature = "saml-identities")]
            Self::Saml(_) => "saml",
            #[cfg(feature = "oidc-identities")]
            Self::Oidc(_) => "oidc",
        }
    }
    #[cfg(any(feature = "oidc-identities", feature = "saml-identities"))]
    pub(super) async fn recheck(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        current: Verifier,
    ) -> Result<()> {
        match self {
            Self::Local(_) => Ok(()),
            #[cfg(feature = "saml-identities")]
            Self::Saml(source) => source.recheck(tx, realm, current).await,
            #[cfg(feature = "oidc-identities")]
            Self::Oidc(source) => source.recheck(tx, realm, current).await,
        }
    }
    pub(super) async fn fresh_session(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        realm: Uuid,
        owner: Uuid,
        current: Verifier,
    ) -> Result<Uuid> {
        match self {
            Self::Local(_) => fresh_session(tx, realm, owner, current).await,
            #[cfg(feature = "saml-identities")]
            Self::Saml(source) => source.fresh_session(tx, realm, owner, current).await,
            #[cfg(feature = "oidc-identities")]
            Self::Oidc(source) => source.fresh_session(tx, realm, owner, current).await,
        }
    }
}
