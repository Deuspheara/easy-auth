use super::{input::optional, policy::OidcVerificationPolicy};
use crate::{Error, OAuthExchange, Result, Secret};
use serde::Deserialize;
use zeroize::Zeroize;

pub(super) const MAX_TOKEN_AGE_SECONDS: u64 = 300;
const MAX_SUBJECT_BYTES: usize = 255;
const MAX_EMAIL_ATTRIBUTE_BYTES: usize = 320;
#[derive(Deserialize)]
#[serde(untagged)]
enum Audience {
    One(String),
    Many(Vec<String>),
}

#[derive(Deserialize)]
pub(super) struct Claims {
    iss: String,
    pub(super) sub: String,
    aud: Audience,
    pub(super) exp: u64,
    pub(super) iat: u64,
    nonce: String,
    #[serde(default, deserialize_with = "optional")]
    azp: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    nbf: Option<u64>,
    #[serde(default, deserialize_with = "optional")]
    pub(super) auth_time: Option<u64>,
    #[serde(default, deserialize_with = "optional")]
    pub(super) email: Option<String>,
    #[serde(default, deserialize_with = "optional")]
    pub(super) email_verified: Option<bool>,
    #[cfg(feature = "oidc-identities")]
    #[serde(default, deserialize_with = "super::profile::attribute")]
    pub(super) name: Option<String>,
    #[cfg(feature = "oidc-identities")]
    #[serde(default, deserialize_with = "super::profile::attribute")]
    pub(super) preferred_username: Option<String>,
}
impl Drop for Claims {
    fn drop(&mut self) {
        self.nonce.zeroize();
    }
}
impl Claims {
    pub(super) fn validate(
        &self,
        exchange: &OAuthExchange,
        policy: &OidcVerificationPolicy,
        now_us: i64,
    ) -> Result<()> {
        if now_us >= exchange.expires_us() {
            return Err(Error::Unauthorized);
        }
        self.validate_times(now_us)?;
        self.validate_audiences(exchange.configuration().provider_client(), policy)?;
        self.validate_attributes()?;
        if self.iss != exchange.configuration().issuer()
            || Secret::parse(self.nonce.clone())?.verifier() != exchange.proof().nonce().verifier()
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn validate_times(&self, now_us: i64) -> Result<()> {
        if now_us < 0 {
            return Err(Error::Unavailable);
        }
        let now = (now_us / 1_000_000) as u64;
        if self.iat > now
            || (i128::from(self.iat) + i128::from(MAX_TOKEN_AGE_SECONDS)) * 1_000_000
                <= i128::from(now_us)
            || self.exp <= self.iat
            || i128::from(self.exp) * 1_000_000 <= i128::from(now_us)
            || self.nbf.is_some_and(|value| value > now)
            || self.auth_time.is_some_and(|value| value > self.iat)
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn validate_audiences(&self, client: &str, policy: &OidcVerificationPolicy) -> Result<()> {
        let audiences: Vec<&str> = match &self.aud {
            Audience::One(value) => vec![value.as_str()],
            Audience::Many(values) => values.iter().map(String::as_str).collect(),
        };
        if audiences.is_empty()
            || audiences.len() > super::policy::MAX_AUDIENCES
            || !audiences.contains(&client)
            || audiences.iter().enumerate().any(|(i, value)| {
                audiences[..i].contains(value)
                    || (*value != client
                        && !policy
                            .additional_audiences
                            .iter()
                            .any(|trusted| trusted == value))
            })
            || self.azp.as_deref().is_some_and(|value| value != client)
            || (audiences.len() > 1 && self.azp.as_deref() != Some(client))
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }

    fn validate_attributes(&self) -> Result<()> {
        if self.sub.is_empty()
            || self.sub.len() > MAX_SUBJECT_BYTES
            || !self.sub.is_ascii()
            || self.sub.chars().any(char::is_control)
            || self.email.as_ref().is_some_and(|value| {
                value.is_empty()
                    || value.len() > MAX_EMAIL_ATTRIBUTE_BYTES
                    || value.chars().any(char::is_control)
            })
        {
            return Err(Error::Unauthorized);
        }
        Ok(())
    }
}
