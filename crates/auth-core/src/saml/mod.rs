#[cfg(feature = "saml-certificates")]
mod certificates;
mod configuration;
#[cfg(feature = "saml-identities")]
mod identities;
mod metadata;
mod prepared;
mod proofs;
mod repository;
mod request_generation;
mod requests;
#[cfg(feature = "saml-verification")]
mod verification;

#[cfg(feature = "saml-certificates")]
pub use certificates::{MAX_SAML_PINNED_CERTIFICATES, SamlCertificateTrust, SamlPinnedCertificate};
pub use configuration::SamlRegistration;
pub use prepared::{SamlPreparedResponse, SamlRequestTiming};
pub use proofs::{SamlBrowserProof, SamlStart};
pub use repository::{SamlRequestAdmission, SamlRequestRepository};
pub use requests::{
    MAX_SAML_PENDING_PER_CONNECTION, SAML_REQUEST_LIFETIME_SECONDS, SamlTransactions,
};

#[cfg(feature = "saml-verification")]
pub use verification::{
    SamlPostResponse, SamlReplayKind, SamlReplayRecord, SamlResponseVerifier,
    SamlVerificationMaterial, SamlVerificationRepository, VerifiedSamlAssertion,
};

#[cfg(test)]
mod tests;

#[cfg(test)]
mod preparation_tests;

#[cfg(feature = "saml-identities")]
pub use identities::{
    SamlIdentityPolicy, SamlIdentityRepository, SamlJitPolicy, SamlMappedIdentity, SamlSignIn,
};

#[cfg(feature = "saml-identities")]
mod deletion;
#[cfg(feature = "saml-identities")]
pub use deletion::{
    SamlDeletionBinding, SamlDeletionRequestContext, SamlDeletionRequestRepository,
    SamlDeletionRequests, SamlPreparedDeletion,
};
