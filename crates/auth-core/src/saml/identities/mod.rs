mod mapped;
mod policy;
#[cfg(test)]
mod tests;

pub use mapped::SamlMappedIdentity;
pub use policy::{SamlIdentityPolicy, SamlJitPolicy};
