use crate::{Error, Result};
use uuid::Uuid;

/// Immutable non-secret associated data. Identity allocation/ownership must come
/// from the final verified repository transaction, never an incoming token/user ID.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct AppleGrantBinding {
    pub(super) realm: Uuid,
    pub(super) connection: Uuid,
    pub(super) client: Uuid,
    pub(super) identity: Uuid,
    pub(super) grant: Uuid,
}
impl AppleGrantBinding {
    pub fn new(
        realm: Uuid,
        connection: Uuid,
        client: Uuid,
        identity: Uuid,
        grant: Uuid,
    ) -> Result<Self> {
        if [realm, connection, client, identity, grant]
            .iter()
            .any(Uuid::is_nil)
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            realm,
            connection,
            client,
            identity,
            grant,
        })
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
    pub fn identity(&self) -> Uuid {
        self.identity
    }
    pub fn grant(&self) -> Uuid {
        self.grant
    }
}
