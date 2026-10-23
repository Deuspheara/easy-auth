use crate::{Postgres, unavailable};
use auth_core::{Error, IssuerClientRegistration, Result};
use uuid::Uuid;

#[derive(sqlx::FromRow)]
struct StoredClient {
    revision: Uuid,
    sector: String,
    redirect_uris: Vec<String>,
    authentication: String,
    secret_verifier: Option<Vec<u8>>,
    redirect_profile: String,
}
impl StoredClient {
    fn registration(self, realm: Uuid, client: Uuid) -> Result<IssuerClientRegistration> {
        let redirects: Vec<_> = self.redirect_uris.iter().map(String::as_str).collect();
        let registration = match (
            self.redirect_profile.as_str(),
            self.authentication.as_str(),
            self.secret_verifier,
        ) {
            ("web_exact", "none", None) => {
                IssuerClientRegistration::public(realm, client, &redirects)
            }
            ("web_exact", "client_secret_basic", Some(verifier)) => {
                IssuerClientRegistration::confidential_from_verifier(
                    realm,
                    client,
                    &redirects,
                    verifier.try_into().map_err(|_| Error::Unavailable)?,
                )
            }
            ("native_loopback", "none", None) => {
                IssuerClientRegistration::public_native_loopback(realm, client, &redirects)
            }
            _ => return Err(Error::Unavailable),
        }
        .map_err(|_| Error::Unavailable)?;
        // Never silently normalize corrupted persisted metadata or select a new
        // sector. Loading does not provision, rotate credentials or enable rows.
        if registration.redirects() != self.redirect_uris || registration.sector() != self.sector {
            return Err(Error::Unavailable);
        }
        registration
            .with_persisted_revision(self.revision)
            .map_err(|_| Error::Unavailable)
    }
}

impl Postgres {
    /// Read trusted persisted configuration after restart without the raw secret.
    /// This point-in-time snapshot grants nothing; every later operation still
    /// checks the whole current enabled definition under its own transaction lock.
    pub async fn load_issuer_client(
        &self,
        realm: Uuid,
        client: Uuid,
    ) -> Result<IssuerClientRegistration> {
        let stored: StoredClient = sqlx::query_as(
            "SELECT revision,sector,redirect_uris,authentication,secret_verifier,redirect_profile FROM auth_issuer_clients WHERE realm_id=$1 AND id=$2 AND enabled AND consent='explicit' AND subject_type='pairwise'",
        )
        .bind(realm).bind(client).fetch_optional(&self.pool).await.map_err(unavailable)?
        .ok_or(Error::Unauthorized)?;
        stored.registration(realm, client)
    }
}
