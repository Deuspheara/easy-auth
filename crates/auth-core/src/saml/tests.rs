use super::SamlRegistration;
use saml_rs::{constants::Binding, metadata::SpMetadata};
use uuid::Uuid;

fn registration() -> SamlRegistration {
    SamlRegistration::unsigned_redirect(
        Uuid::new_v4(),
        Uuid::new_v4(),
        Uuid::new_v4(),
        "urn:example:sp",
        "urn:example:idp",
        "https://idp.example/sso",
        "https://app.example/saml/acs",
    )
    .unwrap()
}

#[test]
fn metadata_roundtrip_advertises_only_the_selected_outgoing_profile() {
    let registration = registration();
    let xml = registration.metadata_xml();
    let metadata = SpMetadata::from_xml(&xml).unwrap();
    assert_eq!(metadata.get_entity_id(), Some(registration.sp_entity()));
    assert_eq!(
        metadata
            .get_assertion_consumer_service(Binding::Post)
            .as_deref(),
        Some(registration.acs())
    );
    assert!(
        metadata
            .get_assertion_consumer_service(Binding::Redirect)
            .is_none()
    );
    assert!(metadata.is_want_assertions_signed());
    assert!(!metadata.is_authn_request_signed());
    assert!(!xml.contains("KeyDescriptor"));
    assert!(!xml.contains("SingleLogoutService"));
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"));
    assert!(!xml.contains("nameid-format:emailAddress"));
}

#[test]
fn outgoing_request_uses_exact_endpoint_and_independent_opaque_relay_state() {
    let registration = registration();
    let relay = crate::Secret::generate().unwrap();
    let first = registration.login_request(relay.expose()).unwrap();
    let second = registration.login_request(relay.expose()).unwrap();
    assert_ne!(first.id, second.id);
    assert!(first.id.starts_with('_'));
    assert_eq!(first.entity_endpoint, registration.sso());
    assert_eq!(first.binding, Binding::Redirect);
    assert_eq!(first.request_type, "SAMLRequest");
    assert!(first.signature.is_none());
    let url = url::Url::parse(&first.context).unwrap();
    assert_eq!(url.origin().ascii_serialization(), "https://idp.example");
    assert_eq!(url.path(), "/sso");
    let pairs: Vec<_> = url.query_pairs().collect();
    assert_eq!(pairs.len(), 2);
    assert!(
        pairs
            .iter()
            .any(|(name, value)| name == "SAMLRequest" && !value.is_empty())
    );
    assert!(
        pairs
            .iter()
            .any(|(name, value)| name == "RelayState" && value == relay.expose())
    );
    let encoded = pairs
        .iter()
        .find(|(name, _)| name == "SAMLRequest")
        .unwrap();
    let compressed = saml_rs::binding::base64_decode(&encoded.1).unwrap();
    let xml =
        String::from_utf8(saml_rs::binding::deflate_raw_decode(&compressed).unwrap()).unwrap();
    assert!(xml.contains(&format!("ID=\"{}\"", first.id)));
    assert!(xml.contains(&format!("Destination=\"{}\"", registration.sso())));
    assert!(xml.contains(&format!(
        "AssertionConsumerServiceURL=\"{}\"",
        registration.acs()
    )));
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"));
    assert!(xml.contains("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"));
}

#[test]
fn registration_keeps_identifiers_exact_and_endpoints_canonical_https() {
    let r = registration();
    assert_eq!(r.reconfigured().sp_entity(), r.sp_entity());
    assert_ne!(r.reconfigured().revision(), r.revision());
    for bad in [
        "http://app.example/acs",
        "https://app.example:443/acs",
        "https://user@app.example/acs",
        "https://app.example/acs?q=1",
        "https://app.example/acs#fragment",
    ] {
        assert!(
            SamlRegistration::unsigned_redirect(
                r.realm(),
                r.connection(),
                r.client(),
                r.sp_entity(),
                r.idp_entity(),
                r.sso(),
                bad
            )
            .is_err()
        );
    }
    for bad in ["", "relative-id", " urn:example:sp", "urn:example:sp\n"] {
        assert!(
            SamlRegistration::unsigned_redirect(
                r.realm(),
                r.connection(),
                r.client(),
                bad,
                r.idp_entity(),
                r.sso(),
                r.acs()
            )
            .is_err()
        );
    }
    assert!(
        SamlRegistration::unsigned_redirect(
            Uuid::nil(),
            r.connection(),
            r.client(),
            r.sp_entity(),
            r.idp_entity(),
            r.sso(),
            r.acs()
        )
        .is_err()
    );
}

#[test]
fn entity_identifiers_respect_metadata_length_and_do_not_publish_userinfo() {
    let r = registration();
    let maximum = format!("urn:{}", "a".repeat(1020));
    assert_eq!(maximum.len(), 1024);
    assert!(
        SamlRegistration::unsigned_redirect(
            r.realm(),
            r.connection(),
            r.client(),
            &maximum,
            r.idp_entity(),
            r.sso(),
            r.acs()
        )
        .is_ok()
    );
    for invalid in [
        format!("{maximum}a"),
        "https://user:private-marker@entity.example/".to_owned(),
    ] {
        assert!(
            SamlRegistration::unsigned_redirect(
                r.realm(),
                r.connection(),
                r.client(),
                &invalid,
                r.idp_entity(),
                r.sso(),
                r.acs()
            )
            .is_err()
        );
    }
}
