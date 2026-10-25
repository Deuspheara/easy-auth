"""Inspect only ordinary outgoing XML from the owned normal-startup fixture.

This is delivery acceptance, not an inbound parser or signature qualification.
Do not print request XML, authorization URLs or private proof cookies.
"""
import base64
from http.cookies import SimpleCookie
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib

METADATA = "urn:oasis:names:tc:SAML:2.0:metadata"
PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol"
ASSERTION = "urn:oasis:names:tc:SAML:2.0:assertion"
POST = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
PERSISTENT = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
COOKIE_NAMES = {"__Host-auth-saml-request", "__Host-auth-saml-relay", "__Host-auth-saml-browser"}


def metadata(base, values):
    with urllib.request.urlopen(base + "/saml/metadata", timeout=3) as response:
        assert response.status == 200
        assert response.headers.get_content_type() == "application/samlmetadata+xml"
        assert "no-store" in response.headers["Cache-Control"]
        assert not response.headers.get_all("Set-Cookie"), "metadata must not create browser authority"
        xml = response.read()
    root = ET.fromstring(xml)
    assert root.tag == "{" + METADATA + "}EntityDescriptor"
    assert root.get("entityID") == values["AUTH_SAML_SP_ENTITY"]
    descriptors = root.findall("{" + METADATA + "}SPSSODescriptor")
    assert len(descriptors) == 1
    descriptor = descriptors[0]
    assert descriptor.get("AuthnRequestsSigned") == "false"
    assert descriptor.get("WantAssertionsSigned") == "true"
    assert descriptor.get("protocolSupportEnumeration") == PROTOCOL
    endpoints = descriptor.findall("{" + METADATA + "}AssertionConsumerService")
    assert len(endpoints) == 1
    assert endpoints[0].attrib == {"Binding": POST, "Location": values["AUTH_PUBLIC_URL"] + "/saml/acs",
                                   "index": "0", "isDefault": "true"}
    formats = descriptor.findall("{" + METADATA + "}NameIDFormat")
    assert len(formats) == 1 and formats[0].text == PERSISTENT
    assert {child.tag for child in descriptor} == {
        "{" + METADATA + "}AssertionConsumerService", "{" + METADATA + "}NameIDFormat"}
    return xml


def request_binding(authorization_url, cookie_headers, values):
    url = urllib.parse.urlsplit(authorization_url)
    assert urllib.parse.urlunsplit(url._replace(query="")) == values["AUTH_SAML_SSO_URL"]
    pairs = urllib.parse.parse_qs(url.query, strict_parsing=True)
    assert set(pairs) == {"SAMLRequest", "RelayState"}
    assert all(len(value) == 1 for value in pairs.values())
    # The production library generated this request; no input or signature is edited.
    request = ET.fromstring(zlib.decompress(base64.b64decode(pairs["SAMLRequest"][0], validate=True), -15))
    assert request.tag == "{" + PROTOCOL + "}AuthnRequest"
    assert request.get("Version") == "2.0"
    assert request.get("Destination") == values["AUTH_SAML_SSO_URL"]
    assert request.get("AssertionConsumerServiceURL") == values["AUTH_PUBLIC_URL"] + "/saml/acs"
    assert request.get("ProtocolBinding") == POST
    assert request.get("ForceAuthn") in (None, "false")
    issuers = request.findall("{" + ASSERTION + "}Issuer")
    assert len(issuers) == 1 and issuers[0].text == values["AUTH_SAML_SP_ENTITY"]
    policies = request.findall("{" + PROTOCOL + "}NameIDPolicy")
    assert len(policies) == 1 and policies[0].get("Format") == PERSISTENT
    assert not request.findall(".//{http://www.w3.org/2000/09/xmldsig#}Signature")
    cookies = proof_cookies(cookie_headers)
    assert cookies["__Host-auth-saml-request"].value == request.get("ID")
    relay = cookies["__Host-auth-saml-relay"].value
    browser = cookies["__Host-auth-saml-browser"].value
    assert relay == pairs["RelayState"][0] and relay != browser
    assert len(relay) == len(browser) == 43


def proof_cookies(headers):
    assert headers and len(headers) == len(COOKIE_NAMES)
    cookies = SimpleCookie()
    for header in headers:
        parsed = SimpleCookie(header)
        assert len(parsed) == 1
        name, cookie = next(iter(parsed.items()))
        assert name in COOKIE_NAMES and name not in cookies
        assert cookie["secure"] and cookie["httponly"] and cookie["samesite"] == "Lax"
        assert cookie["path"] == "/" and not cookie["domain"] and cookie["max-age"] == "300"
        cookies.load(header)
    assert set(cookies) == COOKIE_NAMES
    return cookies
