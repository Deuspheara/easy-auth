use super::*;
use josekit::{
    jwk::{KeyPair, alg::ec::EcKeyPair},
    jws::ES256,
};

pub(super) const TEAM: &str = "TEAM000001";
pub(super) const CLIENT: &str = "com.example.auth";

// The maintained producer generates an owned test key, held fixed throughout
// each scenario. No Apple/operator key, synthetic signature or custom crypto.
pub(super) fn key() -> EcKeyPair {
    ES256.generate_key_pair().unwrap()
}
pub(super) fn pem(key: &EcKeyPair) -> String {
    String::from_utf8(key.to_pem_private_key()).unwrap()
}
pub(super) fn signer(id: &str, start: u64, end: u64) -> (EcKeyPair, AppleClientSecretSigner) {
    let key = key();
    let signer =
        AppleClientSecretSigner::from_pkcs8_pem(TEAM, CLIENT, id, start, end, pem(&key)).unwrap();
    (key, signer)
}

pub(super) fn verify(
    secret: &AppleClientSecret,
    key: &EcKeyPair,
) -> (serde_json::Value, josekit::jws::JwsHeader) {
    let verifier = ES256.verifier_from_pem(key.to_pem_public_key()).unwrap();
    let (payload, header) =
        josekit::jws::deserialize_compact(secret.token.as_bytes(), &verifier).unwrap();
    (serde_json::from_slice(&payload).unwrap(), header)
}
