use super::{AppleClientType, AppleCodeExchange, AppleNonceEncoding};
use crate::{Error, OAuthStart, Result};
use std::fmt;
use zeroize::Zeroizing;

/// Public authorization inputs only. Retain private operation proof separately.
/// Native transport must use Authentication Services; this value launches no UI.
pub struct AppleAuthorizationRequest {
    client_id: String,
    state: Zeroizing<String>,
    nonce: Zeroizing<String>,
    web_url: Option<Zeroizing<String>>,
}
impl AppleAuthorizationRequest {
    pub fn client_id(&self) -> &str {
        &self.client_id
    }
    pub fn state(&self) -> &str {
        &self.state
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn web_url(&self) -> Option<&str> {
        self.web_url.as_deref().map(String::as_str)
    }
}
impl fmt::Debug for AppleAuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AppleAuthorizationRequest([REDACTED])")
    }
}
impl AppleCodeExchange {
    pub(super) async fn authorization(
        &self,
        start: &OAuthStart,
    ) -> Result<AppleAuthorizationRequest> {
        let discovery = self.discovery().await?;
        let state = Zeroizing::new(start.state.expose().to_owned());
        let nonce = Zeroizing::new(
            self.client_type
                .nonce()
                .authorization_nonce(start.proof.nonce()),
        );
        let web_url = if self.client_type == AppleClientType::Web {
            let mut url = url::Url::parse(discovery.authorization_endpoint())
                .map_err(|_| Error::Unavailable)?;
            url.query_pairs_mut()
                .append_pair("response_type", "code")
                .append_pair("response_mode", "form_post")
                .append_pair("scope", "email name")
                .append_pair("client_id", self.configuration().provider_client())
                .append_pair("redirect_uri", self.configuration().redirect())
                .append_pair("state", &state)
                .append_pair("nonce", &nonce);
            Some(Zeroizing::new(url.into()))
        } else {
            None
        };
        Ok(AppleAuthorizationRequest {
            client_id: self.configuration().provider_client().to_owned(),
            state,
            nonce,
            web_url,
        })
    }
    pub fn nonce_encoding(&self) -> AppleNonceEncoding {
        self.client_type.nonce()
    }
}
