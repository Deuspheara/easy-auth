use super::IssuerNativeConsumerPolicy;
use crate::{
    IssuerAccessData, IssuerActiveAccess, IssuerAuthority, IssuerClientRegistration,
    IssuerTokenError, IssuerTokenResult,
};

/// Repository facts only. The policy identifies the actual authorized consumer
/// separately from the token audience; no owner/session/raw credential leaves SQL.
pub struct IssuerNativeAccessData {
    pub policy: IssuerNativeConsumerPolicy,
    pub access: IssuerAccessData,
}
/// Validated native access metadata, never a local authentication proof. The
/// owning transport must label its native scope rather than infer an online grant.
pub struct IssuerNativeActiveAccess(IssuerActiveAccess);
impl IssuerNativeActiveAccess {
    pub(super) fn from_repository(
        data: IssuerNativeAccessData,
        authority: &IssuerAuthority,
        consumer: &IssuerClientRegistration,
    ) -> IssuerTokenResult<Self> {
        if data.policy.authority() != authority || data.policy.consumer() != consumer {
            return Err(IssuerTokenError::Unavailable);
        }
        IssuerActiveAccess::from_repository(data.access, authority, data.policy.audience())
            .map(Self)
    }
    pub fn access(&self) -> &IssuerActiveAccess {
        &self.0
    }
}
