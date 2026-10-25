use super::{OidcClientAuthorization, OidcClientConfiguration, OidcClientError, OidcClientResult};
use crate::{OidcAuthorizationCode, Secret};
use std::collections::BTreeMap;
use zeroize::Zeroizing;

const MAX_CALLBACK_BYTES: usize = 16 * 1024;
const MAX_CALLBACK_FIELDS: usize = 64;
pub(super) fn code(
    configuration: &OidcClientConfiguration,
    pending: &OidcClientAuthorization,
    actual: &str,
) -> OidcClientResult<OidcAuthorizationCode> {
    if actual.len() > MAX_CALLBACK_BYTES
        || actual.contains('\\')
        || actual.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(OidcClientError::Callback);
    }
    let actual = url::Url::parse(actual).map_err(|_| OidcClientError::Callback)?;
    let expected =
        url::Url::parse(&configuration.redirect).map_err(|_| OidcClientError::Configuration)?;
    if actual.origin() != expected.origin()
        || actual.path() != expected.path()
        || actual.fragment().is_some()
        || !actual.username().is_empty()
        || actual.password().is_some()
    {
        return Err(OidcClientError::Callback);
    }
    let mut values = fields(actual.query().unwrap_or_default())?;
    for (name, value) in fields(expected.query().unwrap_or_default())? {
        if values.remove(&name).as_ref().map(|v| v.as_str()) != Some(value.as_str()) {
            return Err(OidcClientError::Callback);
        }
    }
    let state = values.remove("state").ok_or(OidcClientError::Callback)?;
    if Secret::parse(state.to_string())
        .map_err(|_| OidcClientError::Callback)?
        .verifier()
        != pending.state.verifier()
        || values.remove("iss").as_ref().map(|v| v.as_str()) != Some(configuration.issuer.as_str())
    {
        return Err(OidcClientError::Callback);
    }
    let code = values.remove("code");
    if let Some(error) = values.remove("error") {
        if code.is_some() {
            return Err(OidcClientError::Callback);
        }
        return Err(match error.as_str() {
            "access_denied" => OidcClientError::Denied,
            "temporarily_unavailable" | "server_error" => OidcClientError::Unavailable,
            _ => OidcClientError::Protocol,
        });
    }
    let mut code = code.ok_or(OidcClientError::Callback)?;
    OidcAuthorizationCode::parse(std::mem::take(&mut *code)).map_err(|_| OidcClientError::Callback)
}
pub(super) fn fields(query: &str) -> OidcClientResult<BTreeMap<String, Zeroizing<String>>> {
    let mut fields = BTreeMap::new();
    if query.is_empty() {
        return Ok(fields);
    }
    for field in query.split('&') {
        if fields.len() >= MAX_CALLBACK_FIELDS {
            return Err(OidcClientError::Callback);
        }
        let (name, value) = field.split_once('=').unwrap_or((field, ""));
        let name = decode(name)?;
        if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
            return Err(OidcClientError::Callback);
        }
        let value = Zeroizing::new(decode(value)?);
        if fields.insert(name, value).is_some() {
            return Err(OidcClientError::Callback);
        }
    }
    Ok(fields)
}
fn decode(value: &str) -> OidcClientResult<String> {
    let mut bytes = Vec::with_capacity(value.len());
    let mut input = value.bytes();
    while let Some(byte) = input.next() {
        bytes.push(match byte {
            b'+' => b' ',
            b'%' => {
                let high = input
                    .next()
                    .and_then(hex)
                    .ok_or(OidcClientError::Callback)?;
                let low = input
                    .next()
                    .and_then(hex)
                    .ok_or(OidcClientError::Callback)?;
                high * 16 + low
            }
            _ => byte,
        });
    }
    String::from_utf8(bytes).map_err(|_| OidcClientError::Callback)
}
fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}
