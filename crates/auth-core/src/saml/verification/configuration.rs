use crate::SamlRegistration;
use openssl::x509::X509;
use saml_rs::{
    AcsEndpoint, AssertionSignaturePolicy, AudienceValidationPolicy, AuthnRequestSigningPolicy,
    EntityId, IdpDescriptor, MetadataTrustPolicy, NameIdFormat, ResponseSignaturePolicy, Saml,
    SamlError, Sp, SpConfig, SpMetadataConfig, XmlSignatureProfile,
    constants::{Binding, name_id_format},
    metadata::{Endpoint, IdpMetadataConfig, generate_idp_metadata},
};

// Match the selected verifier's established depth ceiling at the first local
// parse, rather than building a deeper tree that the backend cannot accept.
const MAX_VERIFIED_XML_DEPTH: usize = 128;
const MAX_VERIFIED_XML_BYTES: usize = super::input::MAX_POST_RESPONSE_BYTES / 4 * 3;

pub(super) fn acs(reg: &SamlRegistration) -> Result<AcsEndpoint, SamlError> {
    Ok(AcsEndpoint::post(reg.acs())?.with_index(0).mark_default())
}

pub(super) fn sp(reg: &SamlRegistration) -> Result<Saml<Sp>, SamlError> {
    let mut metadata = SpMetadataConfig::new(vec![acs(reg)?]);
    metadata.name_id_format = vec![NameIdFormat::Persistent];
    let mut config = SpConfig::new(EntityId::try_new(reg.sp_entity())?, metadata);
    config.xml.limits.max_depth = MAX_VERIFIED_XML_DEPTH;
    config.xml.limits.max_bytes = MAX_VERIFIED_XML_BYTES;
    config.validation.assertions = AssertionSignaturePolicy::RequireSigned;
    config.validation.responses = ResponseSignaturePolicy::RequireSigned;
    config.validation.xml_signatures = XmlSignatureProfile::StrictRsaSha256;
    config.validation.authn_requests = AuthnRequestSigningPolicy::DoNotSignForCompatibility;
    config.validation.audience = AudienceValidationPolicy::Validate;
    Saml::sp(config)
}

pub(super) fn idp(reg: &SamlRegistration, der: &[u8]) -> Result<IdpDescriptor, crate::Error> {
    let cert = X509::from_der(der).map_err(|_| crate::Error::Unavailable)?;
    let pem = String::from_utf8(cert.to_pem().map_err(|_| crate::Error::Unavailable)?)
        .map_err(|_| crate::Error::Unavailable)?;
    let config = IdpMetadataConfig {
        entity_id: reg.idp_entity().to_owned(),
        signing_certs: vec![pem],
        want_authn_requests_signed: false,
        name_id_format: vec![name_id_format::PERSISTENT.to_owned()],
        single_sign_on_service: vec![Endpoint::new(Binding::Redirect, reg.sso())],
        ..Default::default()
    };
    // This XML is generated solely from our trusted configuration. This import
    // policy permits no remote metadata and changes no inbound signature policy.
    IdpDescriptor::from_metadata_xml_for(
        EntityId::try_new(reg.idp_entity()).map_err(|_| crate::Error::Unavailable)?,
        &generate_idp_metadata(&config),
        MetadataTrustPolicy::UnsignedForCompatibility,
    )
    .map_err(|_| crate::Error::Unavailable)
}
