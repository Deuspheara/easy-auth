//! Complete bearer-profile controls for API comparison; no production authority.
mod engine;

use samael::crypto::{CertificateDer, Crypto, CryptoProvider, ReduceMode};
use samael::idp::response_builder::build_response_template;
use samael::idp::{CertificateParams, IdentityProvider, KeyType, Rsa};
use samael::schema::Assertion;
use samael::signature::{DigestAlgorithm, Signature, SignatureAlgorithm};
use samael::traits::ToXml;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[derive(Clone, Copy)]
enum Target {
    Response,
    Assertion,
}

#[derive(Clone, Copy)]
enum Algorithms {
    Strong,
    WeakDigest,
    WeakSignature,
}

fn main() {
    if run().is_err() {
        eprintln!("profile_comparison_fixture_failed");
        std::process::exit(2);
    }
}

fn run() -> Result<()> {
    let owner = IdentityProvider::generate_new(KeyType::Rsa(Rsa::Rsa2048))?;
    let cert = owner.create_certificate(&CertificateParams {
        common_name: "idp.example.test",
        issuer_name: "idp.example.test",
        days_until_expiration: 1,
    })?;
    for (name, target, algorithms) in [
        (
            "profile-healthy-response",
            Target::Response,
            Algorithms::Strong,
        ),
        (
            "profile-healthy-assertion",
            Target::Assertion,
            Algorithms::Strong,
        ),
        (
            "profile-weak-digest",
            Target::Response,
            Algorithms::WeakDigest,
        ),
        (
            "profile-weak-signature",
            Target::Response,
            Algorithms::WeakSignature,
        ),
    ] {
        let xml = signed_profile(&owner, &cert, target, algorithms)?;
        for mode in [
            ReduceMode::ValidateAndMarkNoAncestors,
            ReduceMode::PreDigest,
        ] {
            engine::emit(name, mode, &xml, std::slice::from_ref(&cert));
        }
    }
    Ok(())
}

fn signed_profile(
    owner: &IdentityProvider,
    cert: &CertificateDer,
    target: Target,
    algorithms: Algorithms,
) -> Result<String> {
    let mut response = build_response_template(
        cert,
        "auth32-trusted-subject",
        "https://sp.example.test",
        "https://idp.example.test",
        "https://sp.example.test/acs",
        "auth32-owned-request",
        &[],
    );
    let assertion = response.assertion.as_mut().ok_or("missing_assertion")?;
    set_bearer_expiry(assertion, chrono::Utc::now() + chrono::Duration::minutes(5))?;
    let id = match target {
        Target::Response => &response.id,
        Target::Assertion => &assertion.id,
    };
    let mut signature = Signature::template(id, cert);
    for reference in &mut signature.signed_info.reference {
        reference.digest_method.algorithm = match algorithms {
            Algorithms::WeakDigest => DigestAlgorithm::Sha1,
            _ => DigestAlgorithm::Sha256,
        };
    }
    if matches!(algorithms, Algorithms::WeakSignature) {
        signature.signed_info.signature_method.algorithm = SignatureAlgorithm::Unsupported(
            "http://www.w3.org/2000/09/xmldsig#rsa-sha1".to_owned(),
        );
    }
    match target {
        Target::Response => response.signature = Some(signature),
        Target::Assertion => {
            response.signature = None;
            assertion.signature = Some(signature);
        }
    }
    Ok(Crypto::sign_xml(
        response.to_string()?,
        &owner.export_private_key_der()?,
    )?)
}

fn set_bearer_expiry(
    assertion: &mut Assertion,
    expiry: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    assertion
        .conditions
        .as_mut()
        .ok_or("missing_conditions")?
        .not_on_or_after = Some(expiry);
    for confirmation in assertion
        .subject
        .as_mut()
        .ok_or("missing_subject")?
        .subject_confirmations
        .as_mut()
        .ok_or("missing_confirmations")?
    {
        confirmation
            .subject_confirmation_data
            .as_mut()
            .ok_or("missing_confirmation_data")?
            .not_on_or_after = Some(expiry);
    }
    Ok(())
}
