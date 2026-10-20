use samael::crypto::{CertificateDer, Crypto, CryptoProvider};
use samael::idp::response_builder::build_response_template;
use samael::idp::{CertificateParams, IdentityProvider, KeyType, Rsa};
use samael::schema::Response;
use samael::signature::DigestAlgorithm;
use samael::traits::ToXml;

pub(super) const TRUSTED: &str = "auth32-trusted-subject";
pub(super) const ATTACKER: &str = "auth32-untrusted-subject";
pub(super) const WRAPPER: &str = "auth32-unsigned-envelope";
pub(super) type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub(super) struct Signer {
    owner: IdentityProvider,
    pub cert: CertificateDer,
}

pub(super) struct Signed {
    pub xml: String,
    pub response_id: String,
}

impl Signer {
    pub fn new() -> Result<Self> {
        let owner = IdentityProvider::generate_new(KeyType::Rsa(Rsa::Rsa2048))?;
        let cert = owner.create_certificate(&CertificateParams {
            common_name: "idp.example.test",
            issuer_name: "idp.example.test",
            days_until_expiration: 1,
        })?;
        Ok(Self { owner, cert })
    }

    pub fn sign(&self, digest: DigestAlgorithm) -> Result<Signed> {
        let mut response = build_response_template(
            &self.cert,
            TRUSTED,
            "https://sp.example.test",
            "https://idp.example.test",
            "https://sp.example.test/acs",
            "auth32-owned-request",
            &[],
        );
        let signature = response
            .signature
            .as_mut()
            .ok_or("missing_template_signature")?;
        for reference in &mut signature.signed_info.reference {
            reference.digest_method.algorithm = digest.clone();
        }
        let xml = Crypto::sign_xml(response.to_string()?, &self.owner.export_private_key_der()?)?;
        Ok(Signed {
            xml,
            response_id: response.id,
        })
    }
}

// Fixture mutation only. No XML parsing or signature verification policy lives here.
pub(super) fn body(xml: &str) -> &str {
    let xml = xml.trim();
    if xml.starts_with("<?xml") {
        xml.split_once("?>").map_or(xml, |(_, body)| body.trim())
    } else {
        xml
    }
}

pub(super) fn unsigned(xml: &str) -> Result<String> {
    let mut response = xml.parse::<Response>()?;
    response.signature = None;
    response.to_string()
}

pub(super) fn altered_signature(xml: &str) -> Result<String> {
    let (prefix, value) = xml
        .split_once("<ds:SignatureValue>")
        .ok_or("owned_signature_value_missing")?;
    let first = value.chars().next().ok_or("owned_signature_value_empty")?;
    if !first.is_ascii_alphanumeric() && first != '+' && first != '/' {
        return Err("owned_signature_encoding_unexpected".into());
    }
    let replacement = if first == 'A' { 'B' } else { 'A' };
    Ok(format!(
        "{prefix}<ds:SignatureValue>{replacement}{}",
        &value[1..]
    ))
}
