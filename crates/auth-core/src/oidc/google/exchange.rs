use crate::{
    Error, OAuthConnection, OAuthExchange, OAuthMixupDefense, OAuthPurpose, OAuthStart,
    OidcAuthorizationCode, OidcAuthorizationUrl, OidcClientAuthentication, OidcCodeExchange,
    OidcConnectionRepository, OidcDocuments, OidcExchangeRepository, OidcHttp,
    OidcSigningAlgorithm, OidcTokenHttp, OidcVerificationPolicy, Result, VerifiedOidcIdentity,
};
use std::sync::Arc;

pub(super) const ISSUER: &str = "https://accounts.google.com";
const ENDPOINT_ORIGINS: &[&str] = &[
    ISSUER,
    "https://oauth2.googleapis.com",
    "https://www.googleapis.com",
];
pub(super) const IDENTITY_SCOPES: &[&str] = &["email", "profile"];

/// Opt-in Google code verification, not a local session or ordinary activation.
/// Retains the original opaque state/S256 context and the shared reviewed verifier.
/// Web/native transport, provider registration and usable account lifecycle require
/// separate evidence. Installed-client wire secrets are not app-authenticity proof.
pub struct GoogleCodeExchange {
    exchange: OidcCodeExchange,
}

impl GoogleCodeExchange {
    /// Use the exact persisted snapshot and the same authoritative repository for
    /// registry/exchange checks. No caller-selected issuer, egress, algorithms,
    /// additional audiences or authentication fallback is accepted here.
    pub fn new(
        connection: OAuthConnection,
        registry: Arc<dyn OidcConnectionRepository>,
        repository: Arc<dyn OidcExchangeRepository>,
        authentication: OidcClientAuthentication,
        http: Arc<dyn OidcHttp>,
        tokens: Arc<dyn OidcTokenHttp>,
    ) -> Result<Self> {
        if connection.issuer() != ISSUER
            || connection.defense() != OAuthMixupDefense::RequireIssuer
            || matches!(&authentication, OidcClientAuthentication::Public)
        {
            return Err(Error::InvalidInput);
        }
        let documents = Arc::new(OidcDocuments::new(
            connection,
            ENDPOINT_ORIGINS,
            registry,
            http,
        )?);
        let policy = OidcVerificationPolicy::new(&[OidcSigningAlgorithm::RS256], &[])?;
        Ok(Self {
            exchange: OidcCodeExchange::new(documents, repository, policy, authentication, tokens),
        })
    }

    pub fn configuration(&self) -> &OAuthConnection {
        self.exchange.configuration()
    }

    /// Explicit eligible-client profile selection, not evidence that the Google
    /// application is verified/configured or its user's authentication is fresh.
    pub fn with_session_age_claims(self) -> super::GoogleSessionAgeCodeExchange {
        super::GoogleSessionAgeCodeExchange::new(self.exchange)
    }

    /// Start must come from matching OAuthTransactions and retain its private
    /// proof in the transport. Fixed openid/email/profile scopes grant no contact.
    pub async fn authorization_url(&self, start: &OAuthStart) -> Result<OidcAuthorizationUrl> {
        self.exchange
            .authorization_url(start, IDENTITY_SCOPES)
            .await
    }

    pub(super) async fn authorization_for_return(
        &self,
        start: &OAuthStart,
        redirect: &str,
    ) -> Result<OidcAuthorizationUrl> {
        self.exchange
            .authorization_for_return(start, IDENTITY_SCOPES, redirect)
            .await
    }

    /// Consume only a previously claimed sign-in context. No token-upload API,
    /// linking authority or inferred provider authentication freshness is added.
    pub async fn exchange(
        &self,
        exchange: OAuthExchange,
        code: OidcAuthorizationCode,
    ) -> Result<VerifiedOidcIdentity> {
        if !matches!(exchange.purpose(), OAuthPurpose::SignIn) {
            return Err(Error::Unauthorized);
        }
        self.exchange.exchange(exchange, code).await
    }
}
