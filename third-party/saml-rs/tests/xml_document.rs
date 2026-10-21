use saml_rs::binding::{base64_encode, deflate_raw_encode};
use saml_rs::constants::{Binding, ParserType};
use saml_rs::flow::{flow, FlowOptions, HttpRequest};
use saml_rs::SamlError;

const AUTHN_REQUEST: &str = concat!(
    "<samlp:AuthnRequest ",
    "xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" ",
    "xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ",
    "ID=\"_request\" Version=\"2.0\" IssueInstant=\"2026-01-01T00:00:00Z\">",
    "<saml:Issuer>https://sp.example.com/metadata</saml:Issuer>",
    "</samlp:AuthnRequest>",
);

fn options(binding: Binding) -> FlowOptions<'static> {
    let mut options = FlowOptions::default();
    options.binding = Some(binding);
    options.parser_type = Some(ParserType::SamlRequest);
    options
}

fn post_request(xml: &str) -> HttpRequest {
    HttpRequest::post(vec![(
        "SAMLRequest".to_string(),
        base64_encode(xml.as_bytes()),
    )])
}

fn redirect_request(xml: &str) -> Result<HttpRequest, SamlError> {
    let compressed = deflate_raw_encode(xml.as_bytes())?;
    Ok(HttpRequest::redirect(vec![(
        "SAMLRequest".to_string(),
        base64_encode(&compressed),
    )]))
}

fn assert_multiple_document_elements(error: SamlError) {
    assert!(matches!(
        error,
        SamlError::Xml(message) if message == "multiple document elements"
    ));
}

#[test]
fn post_flow_rejects_multiple_document_elements() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!("{AUTHN_REQUEST}<garbage/>");
    let error = flow(&options(Binding::Post), &post_request(&xml))
        .err()
        .ok_or("POST flow unexpectedly accepted multiple document elements")?;

    assert_multiple_document_elements(error);
    Ok(())
}

#[test]
fn redirect_flow_rejects_multiple_document_elements() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!("{AUTHN_REQUEST}<garbage/>");
    let error = flow(&options(Binding::Redirect), &redirect_request(&xml)?)
        .err()
        .ok_or("Redirect flow unexpectedly accepted multiple document elements")?;

    assert_multiple_document_elements(error);
    Ok(())
}

#[test]
fn post_flow_accepts_xml_misc_around_document_element() -> Result<(), Box<dyn std::error::Error>> {
    let xml = format!(
        "<?xml version=\"1.0\"?>\n<!-- before --><?before allowed?>{AUTHN_REQUEST}<?after allowed?><!-- after -->"
    );

    flow(&options(Binding::Post), &post_request(&xml))?;
    Ok(())
}

#[test]
fn document_and_root_collection_reject_unclosed_trailing_elements() {
    use saml_rs::xml::dom;
    for xml in [
        "<Root/><Open>",
        "<Root/><Open><Child/>",
        "<Root/><Open><Nested>",
    ] {
        assert!(matches!(dom::parse(xml), Err(SamlError::Xml(_))));
        assert!(matches!(dom::parse_roots(xml), Err(SamlError::Xml(_))));
    }
}

#[test]
fn post_and_redirect_flow_reject_unclosed_trailing_protocol_root(
) -> Result<(), Box<dyn std::error::Error>> {
    let unclosed = AUTHN_REQUEST
        .strip_suffix("</samlp:AuthnRequest>")
        .ok_or("missing fixture closing tag")?;
    let invalid = format!("{AUTHN_REQUEST}{unclosed}");
    for binding in [Binding::Post, Binding::Redirect] {
        let healthy = match binding {
            Binding::Post => post_request(AUTHN_REQUEST),
            _ => redirect_request(AUTHN_REQUEST)?,
        };
        flow(&options(binding), &healthy)?;
        let request = match binding {
            Binding::Post => post_request(&invalid),
            _ => redirect_request(&invalid)?,
        };
        let result = flow(&options(binding), &request);
        assert!(
            matches!(&result, Err(SamlError::Xml(_))),
            "binding={binding:?}, accepted={}",
            result.is_ok()
        );
    }
    Ok(())
}
