use super::OidcClientAuthentication;
use crate::{Error, OAuthExchange, Result, Secret};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::fmt;
use zeroize::Zeroizing;

const MAX_AUTHORIZATION_CODE_BYTES: usize = 2048;
const RESERVED_TOKEN_PARAMETERS: &[&str] = &[
    "grant_type",
    "code",
    "redirect_uri",
    "client_id",
    "client_secret",
    "code_verifier",
    "client_assertion",
    "client_assertion_type",
];

pub(in crate::oidc) fn validate_endpoint(url: &url::Url) -> Result<()> {
    if url.query_pairs().any(|(key, _)| {
        key.chars().any(char::is_control)
            || RESERVED_TOKEN_PARAMETERS.contains(&key.to_ascii_lowercase().as_str())
    }) {
        return Err(Error::Unavailable);
    }
    Ok(())
}
pub struct OidcAuthorizationCode(Zeroizing<String>);
impl OidcAuthorizationCode {
    pub fn parse(value: String) -> Result<Self> {
        let value = Zeroizing::new(value);
        if value.is_empty()
            || value.len() > MAX_AUTHORIZATION_CODE_BYTES
            || value.bytes().any(|b| !(0x20..=0x7e).contains(&b))
        {
            return Err(Error::Unauthorized);
        }
        Ok(Self(value))
    }
}
impl fmt::Debug for OidcAuthorizationCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcAuthorizationCode([REDACTED])")
    }
}

/// Encoded backend request. Accessors are for the trusted HTTPS adapter only.
pub struct OidcTokenRequest {
    form: Zeroizing<String>,
    authorization: Option<Zeroizing<String>>,
}
impl OidcTokenRequest {
    pub fn form(&self) -> &str {
        &self.form
    }
    pub fn authorization(&self) -> Option<&str> {
        self.authorization.as_ref().map(|v| v.as_str())
    }
    pub(super) fn new(
        exchange: &OAuthExchange,
        code: OidcAuthorizationCode,
        authentication: &OidcClientAuthentication,
    ) -> Self {
        Self::for_client(
            exchange.configuration().provider_client(),
            exchange.redirect(),
            exchange.proof().pkce_verifier(),
            code,
            authentication,
        )
    }
    #[cfg(feature = "oidc-client")]
    pub(in crate::oidc) fn refresh(client: &str, token: &str) -> Self {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "refresh_token")
            .append_pair("client_id", client)
            .append_pair("refresh_token", token);
        Self {
            form: Zeroizing::new(form.finish()),
            authorization: None,
        }
    }

    pub(in crate::oidc) fn for_client(
        client: &str,
        redirect: &str,
        pkce: &Secret,
        code: OidcAuthorizationCode,
        authentication: &OidcClientAuthentication,
    ) -> Self {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "authorization_code")
            .append_pair("code", &code.0)
            .append_pair("redirect_uri", redirect)
            .append_pair("code_verifier", pkce.expose());
        let authorization = match authentication {
            OidcClientAuthentication::Public => {
                form.append_pair("client_id", client);
                None
            }
            OidcClientAuthentication::ClientSecretPost(secret) => {
                form.append_pair("client_id", client)
                    .append_pair("client_secret", &secret.0);
                None
            }
            OidcClientAuthentication::ClientSecretBasic(secret) => {
                // RFC6749 uses form encoding on each component before Basic,
                // rather than raw colon concatenation or reqwest::basic_auth.
                let user: String =
                    url::form_urlencoded::byte_serialize(client.as_bytes()).collect();
                let password = Zeroizing::new(
                    url::form_urlencoded::byte_serialize(secret.0.as_bytes()).collect::<String>(),
                );
                let credentials = Zeroizing::new(format!("{user}:{}", password.as_str()));
                Some(Zeroizing::new(format!(
                    "Basic {}",
                    STANDARD.encode(credentials.as_bytes())
                )))
            }
        };
        Self {
            form: Zeroizing::new(form.finish()),
            authorization,
        }
    }
}
impl fmt::Debug for OidcTokenRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OidcTokenRequest([REDACTED])")
    }
}
