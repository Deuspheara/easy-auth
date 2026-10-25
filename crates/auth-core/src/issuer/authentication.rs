use super::{IssuerClientKind, IssuerClientRegistration};
use crate::{Error, Result, Secret, Verifier};
use std::fmt;
use uuid::Uuid;

/// Parsed request authentication, not a client-authentication proof. Public
/// identification creates no authority; a code flow must still require S256.
/// Hashing happens here so callers cannot submit a stored verifier as a secret.
pub struct IssuerClientAuthentication {
    client: Uuid,
    verifier: Option<Verifier>,
}
impl IssuerClientAuthentication {
    pub fn public(client: Uuid) -> Result<Self> {
        Self::new(client, None)
    }
    pub fn basic(client: Uuid, secret: &Secret) -> Result<Self> {
        Self::new(client, Some(secret.verifier()))
    }
    fn new(client: Uuid, verifier: Option<Verifier>) -> Result<Self> {
        if client.is_nil() {
            return Err(Error::InvalidInput);
        }
        Ok(Self { client, verifier })
    }
    pub fn client(&self) -> Uuid {
        self.client
    }
    pub fn kind(&self) -> IssuerClientKind {
        if self.verifier.is_some() {
            IssuerClientKind::ConfidentialBasic
        } else {
            IssuerClientKind::Public
        }
    }
    /// Persistence comparison only. Never expose this in a protocol response.
    pub fn secret_verifier(&self) -> Option<Verifier> {
        self.verifier
    }
    /// Select the exact registered method; credential comparison and current
    /// enabled-definition checks remain in the repository transaction.
    pub fn validate_for(&self, client: &IssuerClientRegistration) -> Result<()> {
        if self.client != client.client() || self.kind() != client.kind() {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
impl fmt::Debug for IssuerClientAuthentication {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerClientAuthentication([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authentication_cannot_substitute_another_client_or_registered_method() {
        let id = Uuid::new_v4();
        let secret = Secret::generate().unwrap();
        let public =
            IssuerClientRegistration::public(Uuid::new_v4(), id, &["https://app.example/cb"])
                .unwrap();
        let confidential = IssuerClientRegistration::confidential(
            public.realm(),
            id,
            public
                .redirects()
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .as_slice(),
            &secret,
        )
        .unwrap();
        let none = IssuerClientAuthentication::public(id).unwrap();
        let basic = IssuerClientAuthentication::basic(id, &secret).unwrap();
        none.validate_for(&public).unwrap();
        basic.validate_for(&confidential).unwrap();
        assert!(none.validate_for(&confidential).is_err());
        assert!(basic.validate_for(&public).is_err());
        assert!(
            IssuerClientAuthentication::public(Uuid::new_v4())
                .unwrap()
                .validate_for(&public)
                .is_err()
        );
        assert_eq!(basic.secret_verifier(), Some(secret.verifier()));
        assert_eq!(
            format!("{basic:?}"),
            "IssuerClientAuthentication([REDACTED])"
        );
        assert!(!format!("{basic:?}").contains(secret.expose()));
        assert!(IssuerClientAuthentication::public(Uuid::nil()).is_err());
        assert!(IssuerClientAuthentication::basic(Uuid::nil(), &secret).is_err());
    }
}
