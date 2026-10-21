use super::FixtureResult;
use auth_core::{SamlCertificateTrust, SamlJitPolicy, SamlPinnedCertificate};
use serde::Deserialize;

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Pin {
    pub der: Vec<u8>,
    pub from: i64,
    pub until: i64,
}
#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Jit {
    Deny,
    Allow,
}
impl From<Jit> for SamlJitPolicy {
    fn from(value: Jit) -> Self {
        match value {
            Jit::Deny => Self::Deny,
            Jit::Allow => Self::Allow,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Setup {
    pub origin: String,
    pub issuer: String,
    pub certificates: Vec<Pin>,
    pub jit: Jit,
}
impl Setup {
    pub fn validate(&self) -> FixtureResult<()> {
        let origin = url::Url::parse(&self.origin)?;
        let issuer = url::Url::parse(&self.issuer)?;
        if origin.scheme() != "https"
            || origin.host_str() != Some("app.example")
            || origin.port().is_none()
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
            || issuer.scheme() != "https"
            || issuer.host_str() != Some("fixture.invalid")
            || issuer.port() != origin.port()
            || !issuer.path().starts_with("/realms/owned-")
            || issuer.query().is_some()
            || issuer.fragment().is_some()
        {
            return Err("owned fixture origins required".into());
        }
        Ok(())
    }
}
pub(super) fn trust(pins: &[Pin]) -> FixtureResult<SamlCertificateTrust> {
    Ok(SamlCertificateTrust::pinned_leaf(
        pins.iter()
            .map(|p| SamlPinnedCertificate::from_der(&p.der, p.from, p.until))
            .collect::<auth_core::Result<Vec<_>>>()?,
    )?)
}
#[derive(Deserialize)]
#[serde(tag = "command", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Command {
    Configure {
        id: u64,
        realm: usize,
        certificates: Vec<Pin>,
        jit: Jit,
    },
    Select {
        id: u64,
        realm: usize,
    },
    Disable {
        id: u64,
    },
    Facts {
        id: u64,
    },
    Close,
}
