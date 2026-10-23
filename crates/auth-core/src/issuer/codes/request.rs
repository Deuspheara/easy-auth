use super::{IssuerAuthority, pkce};
use crate::{Error, IssuerClientRegistration, Result, Verifier};
use std::fmt;
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

/// Untrusted wire fields. No owner/session, consent decision or source policy
/// may be selected here. The initial supported scope is exactly openid.
pub struct IssuerAuthorizationInput<'a> {
    pub client: Uuid,
    pub response_type: &'a str,
    pub redirect_uri: &'a str,
    pub scope: &'a str,
    pub state: &'a str,
    pub nonce: &'a str,
    pub code_challenge: &'a str,
    pub code_challenge_method: &'a str,
}
pub struct IssuerAuthorizationRequest {
    id: Uuid,
    authority: IssuerAuthority,
    client: IssuerClientRegistration,
    redirect: String,
    state: Zeroizing<String>,
    nonce: Zeroizing<String>,
    pkce: Verifier,
}
impl IssuerAuthorizationRequest {
    pub fn new(
        authority: IssuerAuthority,
        client: IssuerClientRegistration,
        input: &IssuerAuthorizationInput<'_>,
    ) -> Result<Self> {
        if client.realm() != authority.realm()
            || client.client() != input.client
            || input.response_type != "code"
            || input.scope != "openid"
            || input.code_challenge_method != "S256"
        {
            return Err(Error::InvalidInput);
        }
        return_uri(&client, input.redirect_uri)?;
        correlation(input.state)?;
        correlation(input.nonce)?;
        Ok(Self {
            id: Uuid::new_v4(),
            authority,
            client,
            redirect: input.redirect_uri.to_owned(),
            state: Zeroizing::new(input.state.to_owned()),
            nonce: Zeroizing::new(input.nonce.to_owned()),
            pkce: pkce::challenge(input.code_challenge)?,
        })
    }
    pub fn authority(&self) -> &IssuerAuthority {
        &self.authority
    }
    pub fn id(&self) -> Uuid {
        self.id
    }
    pub fn client(&self) -> &IssuerClientRegistration {
        &self.client
    }
    pub fn redirect_uri(&self) -> &str {
        &self.redirect
    }
    pub fn state(&self) -> &str {
        &self.state
    }
    pub fn nonce(&self) -> &str {
        &self.nonce
    }
    pub fn pkce_challenge(&self) -> Verifier {
        self.pkce
    }
}
impl fmt::Debug for IssuerAuthorizationRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("IssuerAuthorizationRequest([REDACTED])")
    }
}
pub(super) fn correlation(value: &str) -> Result<()> {
    if value.is_empty() || value.len() > 1024 || value.chars().any(char::is_control) {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
pub(super) fn return_uri(client: &IssuerClientRegistration, actual: &str) -> Result<()> {
    if !client.permits_redirect(actual) {
        return Err(Error::InvalidInput);
    }
    let url = Url::parse(actual).map_err(|_| Error::InvalidInput)?;
    // Reserved response names must not be smuggled through a registered fixed
    // query, including decoded/case-folded variants. No URL is fetched here.
    const RESERVED: &[&str] = &[
        "code",
        "state",
        "iss",
        "error",
        "error_description",
        "error_uri",
        "id_token",
        "access_token",
        "token_type",
        "expires_in",
    ];
    if url
        .query_pairs()
        .any(|(name, _)| RESERVED.contains(&name.to_ascii_lowercase().as_str()))
    {
        return Err(Error::InvalidInput);
    }
    Ok(())
}
