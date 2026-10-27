#[cfg(feature = "apple-grants")]
mod capture;
mod redemption;

use super::{AppleClientSecretSigner, AppleNonceEncoding};
use crate::{
    Error, OAuthConnection, OAuthExchange, OAuthMixupDefense, OAuthPurpose, OAuthRedirectPolicy,
    OidcAuthorizationCode, OidcConnectionRepository, OidcDiscovery, OidcDocuments,
    OidcExchangeRepository, OidcHttp, OidcTokenHttp, OidcTokenVerifier, OidcVerificationPolicy,
    Result, VerifiedOidcIdentity,
};
use std::{sync::Arc, time::Duration};
use tokio::sync::OwnedSemaphorePermit;

pub(super) const ISSUER: &str = "https://appleid.apple.com";
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Exact registered client kind, selected by trusted composition. Native code
/// redemption does not invent a browser redirect or establish OS delivery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppleClientType {
    Web,
    Native(AppleNonceEncoding),
}
impl AppleClientType {
    pub(super) fn nonce(self) -> AppleNonceEncoding {
        match self {
            Self::Web => AppleNonceEncoding::Plain,
            Self::Native(nonce) => nonce,
        }
    }
}

/// Opt-in backend code component. A consumed private operation is mandatory;
/// neither an uploaded ID token nor a successful exchange grants a local session.
pub struct AppleCodeExchange {
    pub(super) documents: Arc<OidcDocuments>,
    repository: Arc<dyn OidcExchangeRepository>,
    signer: Arc<AppleClientSecretSigner>,
    http: Arc<dyn OidcTokenHttp>,
    verifier: OidcTokenVerifier,
    pub(super) client_type: AppleClientType,
}
impl AppleCodeExchange {
    /// Use the persisted exact source and authoritative repositories. Apple has
    /// its own dedicated return binding, not Google's issuer/S256 profile.
    pub fn new(
        connection: OAuthConnection,
        registry: Arc<dyn OidcConnectionRepository>,
        repository: Arc<dyn OidcExchangeRepository>,
        signer: AppleClientSecretSigner,
        client_type: AppleClientType,
        http: Arc<dyn OidcHttp>,
        tokens: Arc<dyn OidcTokenHttp>,
    ) -> Result<Self> {
        Self::with_shared_signer(
            connection,
            registry,
            repository,
            Arc::new(signer),
            client_type,
            http,
            tokens,
        )
    }

    /// Explicitly share the same protected signer/capacity with a revocation
    /// worker. No private key projection, clone or alternative client is created.
    pub fn with_shared_signer(
        connection: OAuthConnection,
        registry: Arc<dyn OidcConnectionRepository>,
        repository: Arc<dyn OidcExchangeRepository>,
        signer: Arc<AppleClientSecretSigner>,
        client_type: AppleClientType,
        http: Arc<dyn OidcHttp>,
        tokens: Arc<dyn OidcTokenHttp>,
    ) -> Result<Self> {
        if connection.issuer() != ISSUER
            || connection.defense() != OAuthMixupDefense::DedicatedRedirect
            || connection.redirect_policy() != OAuthRedirectPolicy::Exact
            || !connection.redirect().starts_with("https://")
            || connection.provider_client() != signer.client_id()
        {
            return Err(Error::InvalidInput);
        }
        let documents = Arc::new(OidcDocuments::new(connection, &[ISSUER], registry, http)?);
        let verifier = OidcTokenVerifier::new(
            documents.clone(),
            repository.clone(),
            OidcVerificationPolicy::apple(client_type.nonce()),
        );
        Ok(Self {
            documents,
            repository,
            signer,
            http: tokens,
            verifier,
            client_type,
        })
    }

    pub fn configuration(&self) -> &OAuthConnection {
        self.documents.connection()
    }
    /// Trusted immutable registration kind; never inferred from a callback.
    pub fn client_type(&self) -> AppleClientType {
        self.client_type
    }

    pub async fn exchange(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<VerifiedOidcIdentity> {
        if !matches!(exchange.purpose(), OAuthPurpose::SignIn) {
            return Err(Error::Unauthorized);
        }
        self.exchange_registered(exchange, code).await
    }

    /// Explicit web-link proof only. Sign-in and deletion inputs remain rejected;
    /// native OS linking is not enabled by this backend entry point.
    #[cfg(feature = "oidc-linking")]
    pub async fn exchange_linking(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<VerifiedOidcIdentity> {
        if !matches!(exchange.purpose(), OAuthPurpose::Link { .. })
            || self.client_type != AppleClientType::Web
        {
            return Err(Error::Unauthorized);
        }
        self.exchange_registered(exchange, code).await
    }

    async fn exchange_registered(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<VerifiedOidcIdentity> {
        if exchange.configuration() != self.configuration()
            || exchange.redirect() != self.configuration().redirect()
        {
            return Err(Error::Unauthorized);
        }
        let lease = self.verifier.lease_operation()?;
        tokio::time::timeout(EXCHANGE_TIMEOUT, self.exchange_inner(exchange, code, lease))
            .await
            .map_err(|_| Error::Unavailable)?
    }

    async fn exchange_inner(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
        lease: Arc<OwnedSemaphorePermit>,
    ) -> Result<VerifiedOidcIdentity> {
        let (response, discovery) = self.redeem(&exchange, code).await?;
        let token = response.id_token()?;
        self.verifier
            .verify_leased(exchange, token, lease, Some(discovery))
            .await
    }

    pub(super) async fn discovery(&self) -> Result<OidcDiscovery> {
        let discovery = self.documents.discovery_when_admitted().await?;
        if discovery.authorization_endpoint() != "https://appleid.apple.com/auth/authorize"
            || discovery.token_endpoint() != "https://appleid.apple.com/auth/token"
            || discovery.jwks_uri() != "https://appleid.apple.com/auth/keys"
            || !discovery
                .token_authentication_methods()
                .iter()
                .any(|method| method == "client_secret_post")
        {
            return Err(Error::Unavailable);
        }
        Ok(discovery)
    }
}
