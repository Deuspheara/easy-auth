use super::{StartupResult, secret_file};
use auth_axum::BrowserConfig;
use auth_core::{
    OAuthConnection, OAuthMixupDefense, OidcClientAuthentication, OidcDisplayNameClaim,
    OidcDocuments, OidcIdentityPolicy, OidcJitPolicy, OidcSigningAlgorithm, OidcVerificationPolicy,
};
use std::collections::BTreeMap;
use uuid::Uuid;

pub(crate) struct Settings {
    connection: Uuid,
    client: Uuid,
    issuer: String,
    provider_client: String,
    origins: Vec<String>,
    authentication: OidcClientAuthentication,
    verification: OidcVerificationPolicy,
    display: OidcDisplayNameClaim,
    jit: OidcJitPolicy,
    defense: OAuthMixupDefense,
}
pub(crate) struct Prepared {
    pub policy: OidcIdentityPolicy,
    pub origins: Vec<String>,
    pub authentication: OidcClientAuthentication,
    pub verification: OidcVerificationPolicy,
}
impl Settings {
    pub(super) fn parse(values: BTreeMap<String, String>) -> StartupResult<Self> {
        let required = |key| {
            values
                .get(key)
                .map(String::as_str)
                .ok_or_else(|| format!("missing required OIDC setting: {key}"))
        };
        let connection = required("AUTH_OIDC_CONNECTION_ID")?
            .parse()
            .map_err(|_| "invalid OIDC connection ID")?;
        let client = required("AUTH_OIDC_LOCAL_CLIENT_ID")?
            .parse()
            .map_err(|_| "invalid OIDC local client ID")?;
        let issuer = required("AUTH_OIDC_ISSUER")?.to_owned();
        let provider_client = required("AUTH_OIDC_PROVIDER_CLIENT_ID")?.to_owned();
        let origins = required("AUTH_OIDC_ALLOWED_ORIGINS")?
            .split(',')
            .map(|v| v.trim().to_owned())
            .collect();
        let method = required("AUTH_OIDC_CLIENT_AUTH_METHOD")?;
        let authentication =
            secret_file::authentication(method, values.get("AUTH_OIDC_CLIENT_SECRET_FILE"))?;
        let verification = verification(required("AUTH_OIDC_SIGNING_ALGORITHMS")?)?;
        let display = display_claim(optional(&values, "AUTH_OIDC_DISPLAY_CLAIM", "sub"))?;
        let jit = jit_policy(optional(&values, "AUTH_OIDC_JIT", "deny"))?;
        let defense = mixup_defense(optional(&values, "AUTH_OIDC_MIXUP_DEFENSE", "issuer"))?;
        Ok(Self {
            connection,
            client,
            issuer,
            provider_client,
            origins,
            authentication,
            verification,
            display,
            jit,
            defense,
        })
    }
    pub fn prepare(self, realm: Uuid, browser: &BrowserConfig) -> StartupResult<Prepared> {
        if !browser.origin().starts_with("https://") {
            return Err("OIDC browser composition requires HTTPS".into());
        }
        let connection = OAuthConnection::new(
            realm,
            self.connection,
            self.client,
            &self.issuer,
            &self.provider_client,
            &format!("{}/oidc/callback", browser.origin()),
            self.defense,
        )?;
        let policy =
            OidcIdentityPolicy::new(connection, &[&self.issuer], self.display)?.with_jit(self.jit);
        let origins: Vec<_> = self.origins.iter().map(String::as_str).collect();
        OidcDocuments::validate_configuration(policy.configuration(), &origins)?;
        Ok(Prepared {
            policy,
            origins: self.origins,
            authentication: self.authentication,
            verification: self.verification,
        })
    }
}
fn optional<'a>(values: &'a BTreeMap<String, String>, key: &str, default: &'a str) -> &'a str {
    values.get(key).map(String::as_str).unwrap_or(default)
}

fn verification(input: &str) -> StartupResult<OidcVerificationPolicy> {
    let algorithms = input
        .split(',')
        .map(|value| match value.trim() {
            "RS256" => Ok(OidcSigningAlgorithm::RS256),
            "PS256" => Ok(OidcSigningAlgorithm::PS256),
            "ES256" => Ok(OidcSigningAlgorithm::ES256),
            _ => Err("unsupported OIDC signing algorithm"),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OidcVerificationPolicy::new(&algorithms, &[])?)
}
fn display_claim(input: &str) -> StartupResult<OidcDisplayNameClaim> {
    match input {
        "sub" => Ok(OidcDisplayNameClaim::Subject),
        "name" => Ok(OidcDisplayNameClaim::Name),
        "preferred_username" => Ok(OidcDisplayNameClaim::PreferredUsername),
        _ => Err("invalid OIDC display claim".into()),
    }
}
fn jit_policy(input: &str) -> StartupResult<OidcJitPolicy> {
    match input {
        "deny" => Ok(OidcJitPolicy::Deny),
        "allow" => Ok(OidcJitPolicy::Allow),
        _ => Err("invalid OIDC JIT policy".into()),
    }
}
fn mixup_defense(input: &str) -> StartupResult<OAuthMixupDefense> {
    match input {
        "issuer" => Ok(OAuthMixupDefense::RequireIssuer),
        "dedicated_redirect" => Ok(OAuthMixupDefense::DedicatedRedirect),
        _ => Err("invalid OIDC mix-up defense".into()),
    }
}
