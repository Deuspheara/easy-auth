use crate::{Error, Result};
use url::Url;
use uuid::Uuid;

/// Trusted stable issuer/realm context. Neither a request-selected issuer nor an
/// authorization proof. The operator owns its HTTPS identity and route namespace.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerAuthority {
    realm: Uuid,
    issuer: String,
}
impl IssuerAuthority {
    pub fn new(realm: Uuid, issuer: &str) -> Result<Self> {
        let url = Url::parse(issuer).map_err(|_| Error::InvalidInput)?;
        if realm.is_nil()
            || issuer.len() > 2048
            || !issuer.is_ascii()
            || issuer.bytes().any(|b| b.is_ascii_control() || b == b' ')
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || url.path().contains('%')
            || url.path().contains("//")
            || (url.as_str() != issuer && url.origin().ascii_serialization() != issuer)
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            realm,
            issuer: issuer.to_owned(),
        })
    }
    pub fn realm(&self) -> Uuid {
        self.realm
    }
    pub fn issuer(&self) -> &str {
        &self.issuer
    }
}
