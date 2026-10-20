use super::{ProbeResult, secret_file};
use auth_core::OidcClientAuthentication;
use std::{collections::BTreeMap, ffi::OsString, net::IpAddr};

const PREFIX: &str = "AUTH_GOOGLE_TEST_";
const MAX_SETTING_BYTES: usize = 8192;
const ALLOWED: &[&str] = &[
    "AUTH_GOOGLE_TEST_CLIENT_ID",
    "AUTH_GOOGLE_TEST_CLIENT_SECRET_FILE",
    "AUTH_GOOGLE_TEST_CLIENT_AUTH_METHOD",
    "AUTH_GOOGLE_TEST_LOOPBACK_IP",
    "AUTH_GOOGLE_TEST_CLAIMS_PROFILE",
];

#[derive(Clone, Copy)]
pub(super) enum ClaimsProfile {
    Base,
    SessionAge,
}
impl ClaimsProfile {
    pub fn name(self) -> &'static str {
        match self {
            Self::Base => "base",
            Self::SessionAge => "session_age",
        }
    }
}

pub(super) struct Settings {
    pub client: String,
    pub authentication: OidcClientAuthentication,
    pub ip: IpAddr,
    pub profile: ClaimsProfile,
}
impl Settings {
    pub fn read() -> ProbeResult<Self> {
        Self::parse(std::env::vars_os())
    }

    pub(super) fn parse(
        values: impl IntoIterator<Item = (OsString, OsString)>,
    ) -> ProbeResult<Self> {
        let mut settings = BTreeMap::new();
        for (name, value) in values {
            if !name.to_string_lossy().starts_with(PREFIX) {
                continue;
            }
            let name = name
                .into_string()
                .map_err(|_| "invalid_google_test_setting")?;
            let value = value
                .into_string()
                .map_err(|_| "invalid_google_test_setting")?;
            if !ALLOWED.contains(&name.as_str())
                || value.len() > MAX_SETTING_BYTES
                || settings.insert(name, value).is_some()
            {
                return Err("invalid_google_test_setting");
            }
        }
        Self::from_values(settings)
    }
    fn from_values(values: BTreeMap<String, String>) -> ProbeResult<Self> {
        let required = |name| values.get(name).ok_or("missing_google_test_setting");
        let client = required("AUTH_GOOGLE_TEST_CLIENT_ID")?.clone();
        let method = required("AUTH_GOOGLE_TEST_CLIENT_AUTH_METHOD")?;
        let file = required("AUTH_GOOGLE_TEST_CLIENT_SECRET_FILE")?;
        if client.is_empty()
            || client.len() > 256
            || client.trim() != client
            || client.chars().any(char::is_control)
        {
            return Err("invalid_google_test_client");
        }
        if !matches!(
            method.as_str(),
            "client_secret_post" | "client_secret_basic"
        ) {
            return Err("registered_client_method_required");
        }
        let ip = loopback(
            values
                .get("AUTH_GOOGLE_TEST_LOOPBACK_IP")
                .map(String::as_str),
        )?;
        let profile = claims_profile(
            values
                .get("AUTH_GOOGLE_TEST_CLAIMS_PROFILE")
                .map(String::as_str),
        )?;
        let authentication = secret_file::authentication(method, Some(file))
            .map_err(|_| "protected_client_secret_file")?;
        Ok(Self {
            client,
            authentication,
            ip,
            profile,
        })
    }
}

fn loopback(value: Option<&str>) -> ProbeResult<IpAddr> {
    match value.unwrap_or("127.0.0.1") {
        "127.0.0.1" => Ok(std::net::Ipv4Addr::LOCALHOST.into()),
        "::1" => Ok(std::net::Ipv6Addr::LOCALHOST.into()),
        _ => Err("literal_loopback_required"),
    }
}
fn claims_profile(value: Option<&str>) -> ProbeResult<ClaimsProfile> {
    match value.unwrap_or("base") {
        "base" => Ok(ClaimsProfile::Base),
        "session_age" => Ok(ClaimsProfile::SessionAge),
        _ => Err("explicit_claims_profile_required"),
    }
}
