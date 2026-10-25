use super::{ALGORITHM, IssuerPublicKey, MAX_ISSUER_PUBLISHED_KEYS};
use crate::{Error, IssuerAuthority, Result};
use async_trait::async_trait;
use serde::Serialize;
use std::sync::Arc;

#[async_trait]
pub trait IssuerMetadataRepository: Send + Sync {
    async fn published_issuer_keys(
        &self,
        authority: &IssuerAuthority,
    ) -> Result<Vec<IssuerPublicKey>>;
}
#[derive(Serialize)]
pub struct IssuerJwksDocument {
    pub keys: Vec<serde_json::Value>,
}
#[derive(Serialize)]
pub struct IssuerDiscoveryDocument {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub response_types_supported: [&'static str; 1],
    pub response_modes_supported: [&'static str; 1],
    pub grant_types_supported: [&'static str; 1],
    pub subject_types_supported: [&'static str; 1],
    pub id_token_signing_alg_values_supported: [&'static str; 1],
    pub token_endpoint_auth_methods_supported: [&'static str; 2],
    pub scopes_supported: [&'static str; 1],
    pub claims_supported: [&'static str; 7],
    pub code_challenge_methods_supported: [&'static str; 1],
    pub authorization_response_iss_parameter_supported: bool,
    pub request_parameter_supported: bool,
    pub request_uri_parameter_supported: bool,
    pub claims_parameter_supported: bool,
}
pub struct IssuerMetadata {
    authority: IssuerAuthority,
    origin: String,
    repository: Arc<dyn IssuerMetadataRepository>,
}
impl IssuerMetadata {
    /// The first HTTP profile has one HTTPS root issuer; path namespaces remain
    /// unsupported rather than being silently mapped to another discovery URL.
    pub fn new(
        authority: IssuerAuthority,
        repository: Arc<dyn IssuerMetadataRepository>,
    ) -> Result<Self> {
        let url = url::Url::parse(authority.issuer()).map_err(|_| Error::InvalidInput)?;
        let origin = url.origin().ascii_serialization();
        if url.path() != "/"
            || (authority.issuer() != origin && authority.issuer() != format!("{origin}/"))
        {
            return Err(Error::InvalidInput);
        }
        Ok(Self {
            authority,
            origin,
            repository,
        })
    }
    pub fn authority(&self) -> &IssuerAuthority {
        &self.authority
    }
    pub fn origin(&self) -> &str {
        &self.origin
    }
    pub async fn jwks(&self) -> Result<IssuerJwksDocument> {
        let keys = self
            .repository
            .published_issuer_keys(&self.authority)
            .await?;
        if keys.is_empty()
            || keys.len() as i64 > MAX_ISSUER_PUBLISHED_KEYS
            || keys
                .iter()
                .enumerate()
                .any(|(i, key)| keys[..i].iter().any(|other| other.id() == key.id()))
        {
            return Err(Error::Unavailable);
        }
        Ok(IssuerJwksDocument {
            keys: keys.into_iter().map(|key| key.document().clone()).collect(),
        })
    }
    pub async fn discovery(&self) -> Result<IssuerDiscoveryDocument> {
        // Missing/corrupt publication is unavailable, never an empty successful
        // JWKS or a claim that an unconfigured source can issue tokens.
        self.jwks().await?;
        Ok(IssuerDiscoveryDocument {
            issuer: self.authority.issuer().to_owned(),
            authorization_endpoint: format!("{}/oidc/authorize", self.origin),
            token_endpoint: format!("{}/oidc/token", self.origin),
            jwks_uri: format!("{}/oidc/jwks", self.origin),
            response_types_supported: ["code"],
            response_modes_supported: ["query"],
            grant_types_supported: ["authorization_code"],
            subject_types_supported: ["pairwise"],
            id_token_signing_alg_values_supported: [ALGORITHM],
            token_endpoint_auth_methods_supported: ["none", "client_secret_basic"],
            scopes_supported: ["openid"],
            claims_supported: ["iss", "sub", "aud", "nonce", "iat", "exp", "auth_time"],
            code_challenge_methods_supported: ["S256"],
            authorization_response_iss_parameter_supported: true,
            request_parameter_supported: false,
            request_uri_parameter_supported: false,
            claims_parameter_supported: false,
        })
    }
}
