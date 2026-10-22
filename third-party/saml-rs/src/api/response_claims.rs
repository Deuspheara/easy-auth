//! Trusted assertion data for the built-in IdP producer.
use super::RespondSso;
use crate::model::Attributes;

impl RespondSso {
    /// Carry the actual established authentication event separately from new
    /// Response/Assertion issuance, for example when serving an existing SSO
    /// session. The caller must authenticate that event. Requires built-in Web
    /// Browser SSO generation; invalid UTC or future instants fail on issuance.
    /// Omitting this option preserves the producer's existing issuance-time default.
    pub fn authentication_instant(mut self, instant: crate::model::SamlInstant) -> Self {
        self.authentication_instant = Some(instant);
        self
    }

    /// Emit exact scalar attributes using the built-in XML writer and signer.
    /// Order, duplicate names, optional NameFormat and value groups are retained.
    /// Cannot be combined with template-configured attributes or custom rendering.
    /// These attributes do not establish authentication or authorization policy.
    pub fn attributes(mut self, attributes: Attributes) -> Self {
        self.attributes = Some(attributes);
        self
    }
}
