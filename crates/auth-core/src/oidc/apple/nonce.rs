use crate::Secret;
use sha2::{Digest, Sha256};

/// Trusted native integration convention. Never infer it from an incoming token.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppleNonceEncoding {
    Plain,
    Sha256Hex,
}
impl AppleNonceEncoding {
    /// Value the native authorization request must actually send to Apple.
    /// Retain the original independent secret in protected operation storage.
    pub fn authorization_nonce(self, nonce: &Secret) -> String {
        match self {
            Self::Plain => nonce.expose().to_owned(),
            Self::Sha256Hex => {
                use std::fmt::Write;
                let mut encoded = String::with_capacity(64);
                for byte in Sha256::digest(nonce.expose().as_bytes()) {
                    write!(&mut encoded, "{byte:02x}").expect("writing a String cannot fail");
                }
                encoded
            }
        }
    }
    pub(in crate::oidc) fn matches(self, actual: &str, expected: &Secret) -> bool {
        match self {
            Self::Plain => Secret::parse(actual.to_owned())
                .is_ok_and(|nonce| nonce.verifier() == expected.verifier()),
            Self::Sha256Hex => actual == self.authorization_nonce(expected),
        }
    }
}
