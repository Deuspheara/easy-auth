//! Concrete RS256 key policy. No request-selected algorithm or generic signer.
mod issuance;
mod key;
mod metadata;
mod public;
mod publication;

pub use key::IssuerSigningKey;
pub use public::IssuerPublicKey;
pub use publication::{IssuerKeyPublication, IssuerSigningSnapshot};

pub const ISSUER_ID_TOKEN_LIFETIME_SECONDS: i64 = 300;
pub const ISSUER_KEY_PROPAGATION_SECONDS: i64 = 300;
pub const MAX_ISSUER_PUBLISHED_KEYS: i64 = 4;

const ALGORITHM: &str = "RS256";
const MIN_RSA_BITS: u32 = 2048;
const MAX_RSA_BITS: u32 = 8192;
const MAX_RSA_EXPONENT_BYTES: usize = 4;
const MAX_PRIVATE_PEM_BYTES: usize = 16 * 1024;
const MAX_PUBLIC_JWK_BYTES: usize = 2048;

#[cfg(test)]
mod tests;

pub use issuance::{
    IssuerSignedCode, IssuerTokenIssuer, IssuerTokenPreparationData, IssuerTokenRepository,
    IssuerTokens,
};

pub use metadata::{
    IssuerDiscoveryDocument, IssuerJwksDocument, IssuerMetadata, IssuerMetadataRepository,
};

#[cfg(feature = "issuer-native-refresh")]
pub use issuance::{
    IssuerClientTokens, IssuerNativeSignedCode, IssuerNativeTokenCommit, IssuerNativeTokenIssuer,
    IssuerNativeTokenPreparationData, IssuerNativeTokenRepository, IssuerNativeTokens,
    MAX_ISSUER_NATIVE_FAMILIES_PER_OWNER_CLIENT,
};
