use super::AppleClientSecret;
use crate::{Error, Result};
use zeroize::Zeroizing;
const MAX_REVOCATION_FORM_BYTES: usize = 64 * 1024;
impl AppleClientSecret {
    pub(in crate::oidc::apple) fn revocation_form(
        self,
        client: &str,
        token: &str,
        hint: &str,
    ) -> Result<Zeroizing<String>> {
        if !matches!(hint, "refresh_token" | "access_token") {
            return Err(Error::InvalidInput);
        }
        let form = Zeroizing::new(
            url::form_urlencoded::Serializer::new(String::new())
                .append_pair("client_id", client)
                .append_pair("client_secret", self.token.as_str())
                .append_pair("token", token)
                .append_pair("token_type_hint", hint)
                .finish(),
        );
        if form.len() > MAX_REVOCATION_FORM_BYTES {
            return Err(Error::Unavailable);
        }
        Ok(form)
    }
}
