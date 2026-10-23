use super::StartupResult;
use auth_axum::BrowserConfig;
use auth_core::{SamlIdentityPolicy, SamlJitPolicy, SamlRegistration};
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) struct Settings {
    connection: Uuid,
    client: Uuid,
    sp: String,
    idp: String,
    sso: String,
    jit: SamlJitPolicy,
}
pub(crate) struct Prepared {
    pub policy: SamlIdentityPolicy,
}
impl Settings {
    pub(super) fn parse(values: BTreeMap<String, String>) -> StartupResult<Self> {
        let required = |key| {
            values
                .get(key)
                .cloned()
                .ok_or_else(|| format!("missing required SAML setting: {key}"))
        };
        let connection = required("AUTH_SAML_CONNECTION_ID")?
            .parse()
            .map_err(|_| "invalid SAML connection ID")?;
        let client = required("AUTH_SAML_LOCAL_CLIENT_ID")?
            .parse()
            .map_err(|_| "invalid SAML local client ID")?;
        let jit = match values
            .get("AUTH_SAML_JIT")
            .map(String::as_str)
            .unwrap_or("deny")
        {
            "deny" => SamlJitPolicy::Deny,
            "allow" => SamlJitPolicy::Allow,
            _ => return Err("invalid SAML JIT policy".into()),
        };
        Ok(Self {
            connection,
            client,
            sp: required("AUTH_SAML_SP_ENTITY")?,
            idp: required("AUTH_SAML_IDP_ENTITY")?,
            sso: required("AUTH_SAML_SSO_URL")?,
            jit,
        })
    }
    pub fn prepare(self, realm: Uuid, browser: &BrowserConfig) -> StartupResult<Prepared> {
        if !browser.origin().starts_with("https://") {
            return Err("SAML browser composition requires HTTPS".into());
        }
        let registration = SamlRegistration::unsigned_redirect(
            realm,
            self.connection,
            self.client,
            &self.sp,
            &self.idp,
            &self.sso,
            &format!("{}/saml/acs", browser.origin()),
        )?;
        Ok(Prepared {
            policy: SamlIdentityPolicy::new(registration).with_jit(self.jit),
        })
    }
}
