use samael::crypto::{CertificateDer, Crypto, CryptoProvider};
use samael::idp::response_builder::build_response_template;
use samael::idp::{CertificateParams, IdentityProvider, KeyType, Rsa};
use samael::schema::Response;
use samael::signature::{DigestAlgorithm, Signature, SignatureAlgorithm};
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
    pub signed_id: String,
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
        self.sign_algorithms(digest, SignatureAlgorithm::RsaSha256)
    }

    pub fn sign_legacy_signature(&self) -> Result<Signed> {
        self.sign_algorithms(
            DigestAlgorithm::Sha256,
            SignatureAlgorithm::Unsupported(
                "http://www.w3.org/2000/09/xmldsig#rsa-sha1".to_owned(),
            ),
        )
    }

    fn sign_algorithms(
        &self,
        digest: DigestAlgorithm,
        algorithm: SignatureAlgorithm,
    ) -> Result<Signed> {
        let mut response = self.response_template();
        let signature = response
            .signature
            .as_mut()
            .ok_or("missing_template_signature")?;
        signature.signed_info.signature_method.algorithm = algorithm;
        for reference in &mut signature.signed_info.reference {
            reference.digest_method.algorithm = digest.clone();
        }
        let xml = Crypto::sign_xml(response.to_string()?, &self.owner.export_private_key_der()?)?;
        Ok(Signed {
            xml,
            signed_id: response.id,
        })
    }

    pub fn sign_assertion(&self) -> Result<Signed> {
        let mut response = self.response_template();
        response.signature = None;
        // This marker is outside the signed Assertion and must not survive reduction.
        response.destination = Some(WRAPPER.to_owned());
        let assertion = response
            .assertion
            .as_mut()
            .ok_or("missing_template_assertion")?;
        let mut signature = Signature::template(&assertion.id, &self.cert);
        for reference in &mut signature.signed_info.reference {
            reference.digest_method.algorithm = DigestAlgorithm::Sha256;
        }
        assertion.signature = Some(signature);
        let signed_id = assertion.id.clone();
        let xml = Crypto::sign_xml(response.to_string()?, &self.owner.export_private_key_der()?)?;
        Ok(Signed { xml, signed_id })
    }

    fn response_template(&self) -> Response {
        build_response_template(
            &self.cert,
            TRUSTED,
            "https://sp.example.test",
            "https://idp.example.test",
            "https://sp.example.test/acs",
            "auth32-owned-request",
            &[],
        )
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
    if let Some(assertion) = &mut response.assertion {
        assertion.signature = None;
    }
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
