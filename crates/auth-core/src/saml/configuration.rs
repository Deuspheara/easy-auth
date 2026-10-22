use crate::{Error, Result};
use url::Url;
use uuid::Uuid;

const MAX_ENTITY_ID_BYTES: usize = 1024;
const MAX_ENDPOINT_BYTES: usize = 2048;

/// Trusted outgoing SP registration, not a verification/certificate policy or
/// approval to accept a SAML Response. Persist the returned fresh revision.
#[derive(Clone, Debug, Eq, PartialEq)]
#[must_use]
pub struct SamlRegistration {
    realm: Uuid,
    connection: Uuid,
    client: Uuid,
    revision: Uuid,
    sp_entity: String,
    idp_entity: String,
    sso: String,
    acs: String,
}

impl SamlRegistration {
    /// Unsigned Redirect AuthnRequests, POST responses and persistent NameID.
    /// Peers requiring signed requests need a separately implemented signing
    /// profile; this constructor cannot downgrade such a peer's configuration.
    pub fn unsigned_redirect(
        realm: Uuid,
        connection: Uuid,
        client: Uuid,
        sp_entity: &str,
        idp_entity: &str,
        sso: &str,
        acs: &str,
    ) -> Result<Self> {
        if realm.is_nil() || connection.is_nil() || client.is_nil() {
            return Err(Error::InvalidInput);
        }
        entity_id(sp_entity)?;
        entity_id(idp_entity)?;
        endpoint(sso)?;
        endpoint(acs)?;
        Ok(Self {
            realm,
            connection,
            client,
            revision: Uuid::new_v4(),
            sp_entity: sp_entity.to_owned(),
            idp_entity: idp_entity.to_owned(),
            sso: sso.to_owned(),
            acs: acs.to_owned(),
        })
    }

    /// Administrative replacement always gets a fresh revision. The repository
    /// retains operator disable and cancels previous-revision pending requests.
    pub fn reconfigured(&self) -> Self {
        let mut next = self.clone();
        next.revision = Uuid::new_v4();
        next
    }

    /// Restore a stored revision during trusted configuration loading. This value
    /// grants no authority: repositories still check the entire current definition.
    pub fn with_persisted_revision(mut self, revision: Uuid) -> Result<Self> {
        if revision.is_nil() {
            return Err(Error::InvalidInput);
        }
        self.revision = revision;
        Ok(self)
    }

    pub fn realm(&self) -> Uuid {
        self.realm
    }
    pub fn connection(&self) -> Uuid {
        self.connection
    }
    pub fn client(&self) -> Uuid {
        self.client
    }
    pub fn revision(&self) -> Uuid {
        self.revision
    }
    pub fn sp_entity(&self) -> &str {
        &self.sp_entity
    }
    pub fn idp_entity(&self) -> &str {
        &self.idp_entity
    }
    pub fn sso(&self) -> &str {
        &self.sso
    }
    pub fn acs(&self) -> &str {
        &self.acs
    }
}

fn bounded(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control)
}

fn entity_id(value: &str) -> Result<()> {
    if !bounded(value, MAX_ENTITY_ID_BYTES) {
        return Err(Error::InvalidInput);
    }
    let url = Url::parse(value).map_err(|_| Error::InvalidInput)?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(Error::InvalidInput);
    }
    // Entity IDs are exact identifiers, not fetch targets; URNs remain valid.
    Ok(())
}

fn endpoint(value: &str) -> Result<()> {
    if !bounded(value, MAX_ENDPOINT_BYTES) {
        return Err(Error::InvalidInput);
    }
    let url = Url::parse(value).map_err(|_| Error::InvalidInput)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.as_str() != value
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
