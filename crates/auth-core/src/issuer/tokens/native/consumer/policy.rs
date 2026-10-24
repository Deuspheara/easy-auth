use crate::{
    Error, IssuerAuthority, IssuerClientKind, IssuerClientRegistration, IssuerRedirectProfile,
    Result,
};
use uuid::Uuid;

/// Trusted consumer-to-native-audience configuration, never authentication or
/// consent. New persisted rows start disabled. Both complete current client
/// definitions and this exact policy must be locked for every active result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IssuerNativeConsumerPolicy {
    authority: IssuerAuthority,
    consumer: IssuerClientRegistration,
    audience: IssuerClientRegistration,
    revision: Uuid,
}
impl IssuerNativeConsumerPolicy {
    pub fn new(
        authority: IssuerAuthority,
        consumer: IssuerClientRegistration,
        audience: IssuerClientRegistration,
    ) -> Result<Self> {
        if consumer.realm() != authority.realm()
            || audience.realm() != authority.realm()
            || consumer.client() == audience.client()
            || consumer.kind() != IssuerClientKind::ConfidentialBasic
            || audience.redirect_profile() != IssuerRedirectProfile::NativeRefreshLoopback
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            authority,
            consumer,
            audience,
            revision: Uuid::new_v4(),
        })
    }
    pub fn authority(&self) -> &IssuerAuthority {
        &self.authority
    }
    pub fn consumer(&self) -> &IssuerClientRegistration {
        &self.consumer
    }
    pub fn audience(&self) -> &IssuerClientRegistration {
        &self.audience
    }
    pub fn revision(&self) -> Uuid {
        self.revision
    }
    pub fn reconfigured(&self) -> Self {
        let mut next = self.clone();
        next.revision = Uuid::new_v4();
        next
    }
    /// Configuration restoration only; no enabled/current check is inferred.
    pub fn with_persisted_revision(mut self, revision: Uuid) -> Result<Self> {
        if revision.is_nil() {
            return Err(Error::InvalidInput);
        }
        self.revision = revision;
        Ok(self)
    }
}
