use super::{
    engine,
    fixture::{self, Result, Signer, TRUSTED},
};
use samael::crypto::ReduceMode;
use samael::signature::DigestAlgorithm;

const SENTINEL: &str = "/tmp/auth32-owned-sentinel";

pub(super) fn run(arguments: &[String]) -> Result<()> {
    if arguments.len() != 1 {
        return Err("explicit_trap_port_required".into());
    }
    let port: u16 = arguments[0].parse()?;
    if port == 0 {
        return Err("trap_port_required".into());
    }
    let signer = Signer::new()?;
    let response = signer.sign(DigestAlgorithm::Sha256)?;
    let assertion = signer.sign_assertion()?;
    if response.xml.matches(TRUSTED).count() != 1 {
        return Err("owned_subject_marker_not_unique".into());
    }
    let mut inputs = vec![
        ("resource-healthy-response-before", response.xml.clone()),
        ("resource-healthy-assertion-before", assertion.xml.clone()),
    ];
    inputs.extend(forbidden_inputs(fixture::body(&response.xml), port));
    inputs.extend([
        ("resource-healthy-response-after", response.xml),
        ("resource-healthy-assertion-after", assertion.xml),
    ]);
    print!("{{\"rows\":[");
    for (index, ((case, xml), mode)) in inputs
        .iter()
        .flat_map(|input| {
            [
                ReduceMode::ValidateAndMarkNoAncestors,
                ReduceMode::PreDigest,
            ]
            .into_iter()
            .map(move |mode| (input, mode))
        })
        .enumerate()
    {
        if index > 0 {
            print!(",");
        }
        engine::emit(case, mode, xml, std::slice::from_ref(&signer.cert));
    }
    println!("]}}");
    Ok(())
}

fn forbidden_inputs(body: &str, port: u16) -> Vec<(&'static str, String)> {
    let entity_body = body.replace(TRUSTED, "&marker;");
    vec![
        ("resource-doctype", format!("<!DOCTYPE saml2p:Response>{body}")),
        (
            "resource-internal-entity",
            format!("<!DOCTYPE saml2p:Response [<!ENTITY marker '{TRUSTED}'>]>{entity_body}"),
        ),
        (
            "resource-file-entity",
            format!("<!DOCTYPE saml2p:Response [<!ENTITY marker SYSTEM 'file://{SENTINEL}'>]>{entity_body}"),
        ),
        (
            "resource-http-entity",
            format!("<!DOCTYPE saml2p:Response [<!ENTITY marker SYSTEM 'http://127.0.0.1:{port}/entity'>]>{entity_body}"),
        ),
        (
            "resource-external-dtd",
            format!("<!DOCTYPE saml2p:Response SYSTEM 'http://127.0.0.1:{port}/dtd'>{body}"),
        ),
        (
            "resource-parameter-entity",
            format!("<!DOCTYPE saml2p:Response [<!ENTITY % remote SYSTEM 'http://127.0.0.1:{port}/dtd'>%remote;]>{body}"),
        ),
    ]
}
