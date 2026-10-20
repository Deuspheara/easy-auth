use auth_core::*;

pub(super) const REQUEST_SOURCE: &str = "owned-google-desktop";

pub(super) struct Attempt {
    pub start: GoogleAuthorizationStart,
    pub browser: Secret,
    pub code: Secret,
    pub cap: i64,
}
impl Attempt {
    pub fn intent(&self) -> OAuthIntent<'_> {
        OAuthIntent {
            browser: &self.browser,
            source: REQUEST_SOURCE,
            purpose: OAuthPurpose::SignIn,
        }
    }
    pub fn proof(&self) -> OAuthBrowserProof {
        OAuthBrowserProof::parse(
            self.start.transaction.proof.nonce().expose().to_owned(),
            self.start
                .transaction
                .proof
                .pkce_verifier()
                .expose()
                .to_owned(),
        )
        .unwrap()
    }
    pub fn state(&self) -> &Secret {
        &self.start.transaction.state
    }
    pub fn query(&self, error: Option<&str>) -> String {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("state", self.state().expose())
            .append_pair("iss", super::provider::ISSUER);
        if let Some(error) = error {
            form.append_pair("error", error)
                .append_pair("error_description", "private-provider-detail");
        } else {
            form.append_pair("code", self.code.expose())
                .append_pair("scope", "openid email profile")
                .append_pair("authuser", "0");
        }
        form.finish()
    }
    /// Only for backend replay/race controls, never an actual-delivery constructor.
    pub fn replay_response(&self) -> GoogleAuthorizationResponse {
        GoogleAuthorizationResponse::parse(&self.query(None)).unwrap()
    }
}
