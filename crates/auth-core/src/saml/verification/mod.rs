mod attributes;
mod configuration;
mod flow;
mod input;
mod projection;
mod replay;
mod repository;
mod subject;
mod timing;
mod verified;

pub use attributes::SamlAttribute;
pub use flow::SamlResponseVerifier;
pub use input::SamlPostResponse;
pub use replay::{SamlReplayKind, SamlReplayRecord};
pub use repository::{SamlVerificationMaterial, SamlVerificationRepository};
pub use verified::VerifiedSamlAssertion;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod subject_tests;
