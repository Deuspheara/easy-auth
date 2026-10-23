use super::super::IssuerWebServices;
use auth_core::{
    IssuerNativeAuthorization, IssuerNativeRefresh, IssuerNativeRefreshRepository,
    IssuerNativeTokenIssuer, IssuerNativeTokenRepository, IssuerTokenManagement,
    IssuerTokenStatusRepository,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct IssuerNativeWebServices {
    pub(super) base: IssuerWebServices,
    pub(super) consent: Arc<IssuerNativeAuthorization>,
    pub(super) tokens: Arc<IssuerNativeTokenIssuer>,
    pub(super) refresh: Arc<IssuerNativeRefresh>,
    pub(super) management: Arc<IssuerTokenManagement>,
}
impl IssuerNativeWebServices {
    /// Trusted same-authority composition. Uses the base concrete signer's
    /// original engine/capacity, never provisioning keys or enabling policies.
    pub fn new(
        base: IssuerWebServices,
        native: Arc<dyn IssuerNativeTokenRepository>,
        refresh: Arc<dyn IssuerNativeRefreshRepository>,
        status: Arc<dyn IssuerTokenStatusRepository>,
    ) -> Self {
        let authority = base.tokens.authority().clone();
        Self {
            consent: Arc::new(IssuerNativeAuthorization::new(
                authority.clone(),
                native.clone(),
            )),
            tokens: Arc::new(IssuerNativeTokenIssuer::new(&base.tokens, native)),
            refresh: Arc::new(IssuerNativeRefresh::new(authority.clone(), refresh)),
            management: Arc::new(IssuerTokenManagement::new(authority, status)),
            base,
        }
    }
}
