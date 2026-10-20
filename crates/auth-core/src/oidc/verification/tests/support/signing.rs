use crate::{OidcIdToken, OidcSigningAlgorithm};
use josekit::{
    jwk::KeyPair,
    jws::{self, ES256, JwsHeader, JwsSigner, PS256, RS256},
};
use serde_json::Value;

pub(in super::super) struct Signing {
    pub signer: Box<dyn JwsSigner>,
    pub public: Value,
    pub kid: String,
}
impl Signing {
    pub fn with_header(&self, header: &[u8], claims: &Value) -> String {
        use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
        let input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header),
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap())
        );
        // Malformed-header fixture only: real established-library signatures over
        // original duplicate/extension JSON that a map builder would normalize.
        let signature = self.signer.sign(input.as_bytes()).unwrap();
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(signature))
    }

    pub fn new(algorithm: OidcSigningAlgorithm, kid: &str) -> Self {
        let (signer, mut public): (Box<dyn JwsSigner>, _) = match algorithm {
            OidcSigningAlgorithm::ES256 => {
                let k = ES256.generate_key_pair().unwrap();
                (
                    Box::new(ES256.signer_from_der(k.to_der_private_key()).unwrap()),
                    k.to_jwk_public_key(),
                )
            }
            OidcSigningAlgorithm::RS256 => {
                let k = RS256.generate_key_pair(2048).unwrap();
                (
                    Box::new(RS256.signer_from_der(k.to_der_private_key()).unwrap()),
                    k.to_jwk_public_key(),
                )
            }
            OidcSigningAlgorithm::PS256 => {
                let k = PS256.generate_key_pair(2048).unwrap();
                (
                    Box::new(PS256.signer_from_der(k.to_der_private_key()).unwrap()),
                    k.to_jwk_public_key(),
                )
            }
        };
        public.set_key_id(kid);
        public.set_algorithm(algorithm.name());
        public.set_key_use("sig");
        Self {
            signer,
            public: serde_json::to_value(public).unwrap(),
            kid: kid.into(),
        }
    }
    pub fn token(&self, claims: &Value) -> OidcIdToken {
        OidcIdToken::parse(self.raw(&serde_json::to_vec(claims).unwrap())).unwrap()
    }
    pub fn raw(&self, claims: &[u8]) -> String {
        let mut header = JwsHeader::new();
        header.set_token_type("JWT");
        header.set_key_id(&self.kid);
        jws::serialize_compact(claims, &header, self.signer.as_ref()).unwrap()
    }
}
