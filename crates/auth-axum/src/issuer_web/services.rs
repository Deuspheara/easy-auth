use auth_core::{
    IssuerAuthority, IssuerAuthorization, IssuerMetadata, IssuerMetadataRepository,
    IssuerSigningKey, IssuerTokenIssuer, IssuerTokenRepository, Result,
};
use std::sync::Arc;

#[derive(Clone)]
pub struct IssuerWebServices {
    pub(super) authorization: Arc<IssuerAuthorization>,
    pub(super) tokens: Arc<IssuerTokenIssuer>,
    pub(super) metadata: Arc<IssuerMetadata>,
}
impl IssuerWebServices {
    /// Trusted exact realm/issuer composition. Private keys come from protected
    /// operator input; no provisioning, default key or startup activation occurs.
    pub fn new(
        authority: IssuerAuthority,
        repository: Arc<dyn IssuerTokenRepository>,
        metadata: Arc<dyn IssuerMetadataRepository>,
        keys: Vec<Arc<IssuerSigningKey>>,
    ) -> Result<Self> {
        Ok(Self {
            authorization: Arc::new(IssuerAuthorization::new(
                authority.clone(),
                repository.clone(),
            )),
            tokens: Arc::new(IssuerTokenIssuer::new(authority.clone(), repository, keys)?),
            metadata: Arc::new(IssuerMetadata::new(authority, metadata)?),
        })
    }
}
