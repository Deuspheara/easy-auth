use super::super::IssuerWebServices;
use auth_core::{
    IssuerNativeAuthorization, IssuerNativeRefresh, IssuerNativeRefreshRepository,
    IssuerNativeTokenIssuer, IssuerNativeTokenRepository, IssuerTokenManagement,
    IssuerTokenStatusRepository,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct IssuerNativeWebServices {
    pub(super) introspection: Option<Arc<auth_core::IssuerNativeIntrospection>>,
    pub(super) base: IssuerWebServices,
    pub(super) consent: Arc<IssuerNativeAuthorization>,
    pub(super) tokens: Arc<IssuerNativeTokenIssuer>,
    pub(super) refresh: Arc<IssuerNativeRefresh>,
    pub(super) management: Arc<IssuerTokenManagement>,
}
impl IssuerNativeWebServices {
    /// Explicitly mount native consumer inspection. This neither provisions nor
    /// enables any persisted consumer/audience permission.
    pub fn with_native_introspection(
        mut self,
        repository: Arc<dyn auth_core::IssuerNativeIntrospectionRepository>,
    ) -> Self {
        self.introspection = Some(Arc::new(auth_core::IssuerNativeIntrospection::new(
            self.base.tokens.authority().clone(),
            repository,
        )));
        self
    }
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
            introspection: None,
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
