use crate::{
    Error, IssuerAuthorizationInput, IssuerAuthorizationRequest, IssuerNativeRefreshPolicy, Result,
};

/// Untrusted native fields. Explicit consent is mandatory; no automatic approval
/// or upgrade from an earlier online openid authorization is supported.
pub struct IssuerNativeAuthorizationInput<'a> {
    pub authorization: IssuerAuthorizationInput<'a>,
    pub prompt: &'a str,
}
pub struct IssuerNativeAuthorizationRequest {
    code: IssuerAuthorizationRequest,
    policy: IssuerNativeRefreshPolicy,
}
impl IssuerNativeAuthorizationRequest {
    pub fn new(
        policy: IssuerNativeRefreshPolicy,
        input: &IssuerNativeAuthorizationInput<'_>,
    ) -> Result<Self> {
        if input.prompt != "consent" || input.authorization.scope != "openid offline_access" {
            return Err(Error::InvalidInput);
        }
        let code = IssuerAuthorizationRequest::validated(
            policy.authority().clone(),
            policy.client().clone(),
            &input.authorization,
        )?;
        Ok(Self { code, policy })
    }
    /// Validated request bindings, not an approved online or offline grant. The
    /// default online repository must continue refusing this client's profile.
    pub fn code(&self) -> &IssuerAuthorizationRequest {
        &self.code
    }
    pub fn policy(&self) -> &IssuerNativeRefreshPolicy {
        &self.policy
    }
}
