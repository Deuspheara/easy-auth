use std::fmt;
use zeroize::Zeroizing;

/// Exact scalar attribute data from the signature-covered Assertion. These
/// values are presentation/provider data, never ownership or permission grants.
pub struct SamlAttribute {
    name: Zeroizing<String>,
    name_format: Option<Zeroizing<String>>,
    values: Zeroizing<Vec<String>>,
}

impl SamlAttribute {
    pub fn name(&self) -> &str {
        &self.name
    }
    /// None is distinct from an explicitly supplied empty NameFormat.
    pub fn name_format(&self) -> Option<&str> {
        self.name_format.as_ref().map(|value| value.as_str())
    }
    /// Exact document-order text; empty and repeated values are retained.
    pub fn values(&self) -> &[String] {
        &self.values
    }
}

impl fmt::Debug for SamlAttribute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SamlAttribute([REDACTED])")
    }
}

pub(super) fn project(session: &saml_rs::SsoSession) -> crate::Result<Vec<SamlAttribute>> {
    // The existing input/XML limits bound this collection. Never aggregate by
    // name, normalize values, infer NameFormat, or fall back to an email key.
    Ok(session
        .attribute_records()
        .ok_or(crate::Error::Unauthorized)?
        .as_slice()
        .iter()
        .map(|attribute| SamlAttribute {
            name: Zeroizing::new(attribute.name().to_owned()),
            name_format: attribute
                .name_format()
                .map(|value| Zeroizing::new(value.to_owned())),
            values: Zeroizing::new(
                attribute
                    .values()
                    .iter()
                    .map(|value| value.as_str().to_owned())
                    .collect(),
            ),
        })
        .collect())
}
