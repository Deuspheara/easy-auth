mod configuration;
mod metadata;
mod proofs;
mod repository;
mod requests;

pub use configuration::SamlRegistration;
pub use proofs::{SamlBrowserProof, SamlStart};
pub use repository::{SamlRequestAdmission, SamlRequestRepository};
pub use requests::{
    MAX_SAML_PENDING_PER_CONNECTION, SAML_REQUEST_LIFETIME_SECONDS, SamlTransactions,
};

#[cfg(test)]
mod tests;
