use super::super::work::SignatureWork;
use super::{
    OidcClientAuthorization, OidcClientConfiguration, OidcClientError, OidcClientResult,
    error::infrastructure,
};
use crate::{
    OidcDiscovery, OidcTokenHttp,
    oidc::documents::{DocumentContext, DocumentRetrieval},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use std::{sync::Arc, time::Duration};
use uuid::Uuid;

const CLIENT_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
/// Independent relying party. Its own private operation state and metadata never
/// acquire provider-cookie or local-session authority.
pub struct OidcClient {
    pub(super) id: Uuid,
    pub(super) configuration: OidcClientConfiguration,
    pub(super) documents: DocumentRetrieval,
    pub(super) http: Arc<dyn OidcTokenHttp>,
    pub(super) work: SignatureWork,
}
impl OidcClient {
    pub fn new(
        configuration: OidcClientConfiguration,
        documents_http: Arc<dyn crate::OidcHttp>,
        http: Arc<dyn OidcTokenHttp>,
    ) -> OidcClientResult<Self> {
        let documents = DocumentRetrieval::new(configuration.policy()?, documents_http);
        Ok(Self {
            id: Uuid::new_v4(),
            configuration,
            documents,
            http,
            work: SignatureWork::new(),
        })
    }
    pub async fn discovery(&self) -> OidcClientResult<OidcDiscovery> {
        self.documents
            .discovery(self.context())
            .await
            .map_err(infrastructure)
    }
    pub(super) fn context(&self) -> DocumentContext<'_> {
        DocumentContext::client(&self.configuration.issuer)
    }
    pub async fn authorize(&self) -> OidcClientResult<OidcClientAuthorization> {
        let _lease = self.work.lease().map_err(infrastructure)?;
        tokio::time::timeout(CLIENT_OPERATION_TIMEOUT, async {
            let discovery = self
                .documents
                .discovery_when_admitted(self.context())
                .await
                .map_err(infrastructure)?;
            if !discovery.supports_s256()
                || !discovery
                    .token_authentication_methods()
                    .iter()
                    .any(|v| v == self.configuration.authentication.method())
            {
                return Err(OidcClientError::Configuration);
            }
            let mut pending = OidcClientAuthorization::new(self.id)?;
            let mut url = url::Url::parse(discovery.authorization_endpoint())
                .map_err(|_| OidcClientError::Protocol)?;
            super::super::exchange::validate_authorization_endpoint(&url)
                .map_err(|_| OidcClientError::Protocol)?;
            url.query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.configuration.client.to_string())
                .append_pair("redirect_uri", &self.configuration.redirect)
                .append_pair(
                    "scope",
                    if self.configuration.offline {
                        "openid offline_access"
                    } else {
                        "openid"
                    },
                )
                .append_pair("state", pending.state.expose())
                .append_pair("nonce", pending.nonce.expose())
                .append_pair(
                    "code_challenge",
                    &URL_SAFE_NO_PAD.encode(pending.pkce.verifier()),
                )
                .append_pair("code_challenge_method", "S256");
            if self.configuration.offline {
                url.query_pairs_mut().append_pair("prompt", "consent");
            }
            pending.url = zeroize::Zeroizing::new(url.into());
            pending.check(self.id)?;
            Ok(pending)
        })
        .await
        .map_err(|_| OidcClientError::Unavailable)?
    }
}
