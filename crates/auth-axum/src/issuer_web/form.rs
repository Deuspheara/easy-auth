use super::error::{TokenHttpError, invalid};
use axum::http::{HeaderMap, StatusCode, header};
use std::collections::BTreeMap;

pub(super) use super::types::TokenFormSchema as TokenForm;
impl TokenForm {
    pub fn parse(headers: &HeaderMap, body: &[u8]) -> Result<Self, TokenHttpError> {
        let mut fields = fields(headers, body)?;
        if fields.keys().any(|name| {
            ![
                "grant_type",
                "code",
                "redirect_uri",
                "code_verifier",
                "client_id",
            ]
            .contains(&name.as_str())
        }) {
            return Err(invalid());
        }
        let mut required = |name| {
            fields
                .remove(name)
                .filter(|v| !v.is_empty())
                .ok_or_else(invalid)
        };
        let grant_type = required("grant_type")?;
        let code = required("code")?;
        let redirect_uri = required("redirect_uri")?;
        let verifier = required("code_verifier")?;
        Ok(Self {
            grant_type,
            code,
            redirect_uri,
            code_verifier: verifier,
            client_id: fields.remove("client_id"),
        })
    }
}
/// Shared strict form decoding; each operation owns its closed allowed/required
/// member policy. Percent-decoded duplicate names are rejected before selection.
pub(super) fn fields(
    headers: &HeaderMap,
    body: &[u8],
) -> Result<BTreeMap<String, String>, TokenHttpError> {
    content_type(headers)?;
    let raw = std::str::from_utf8(body).map_err(|_| invalid())?;
    let mut fields = BTreeMap::new();
    for pair in raw.split('&') {
        let (name, value) = pair.split_once('=').ok_or_else(invalid)?;
        let name = component(name)?;
        let value = component(value)?;
        if fields.insert(name, value).is_some() {
            return Err(invalid());
        }
    }
    Ok(fields)
}
pub(super) fn component(input: &str) -> Result<String, TokenHttpError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => out.push(b' '),
            b'%' => {
                let high = bytes
                    .get(index + 1)
                    .and_then(|b| char::from(*b).to_digit(16))
                    .ok_or_else(invalid)?;
                let low = bytes
                    .get(index + 2)
                    .and_then(|b| char::from(*b).to_digit(16))
                    .ok_or_else(invalid)?;
                out.push((high * 16 + low) as u8);
                index += 2;
            }
            value => out.push(value),
        }
        index += 1;
    }
    String::from_utf8(out).map_err(|_| invalid())
}
fn content_type(headers: &HeaderMap) -> Result<(), TokenHttpError> {
    let unsupported = || TokenHttpError::InvalidRequest(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    if headers.contains_key(header::CONTENT_ENCODING)
        || headers.get_all(header::CONTENT_TYPE).iter().count() != 1
    {
        return Err(unsupported());
    }
    let value = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(unsupported)?;
    let mut parts = value.split(';').map(str::trim);
    if !parts
        .next()
        .is_some_and(|p| p.eq_ignore_ascii_case("application/x-www-form-urlencoded"))
    {
        return Err(unsupported());
    }
    if let Some(option) = parts.next()
        && (!(option.eq_ignore_ascii_case("charset=utf-8")
            || option.eq_ignore_ascii_case("charset=\"utf-8\""))
            || parts.next().is_some())
    {
        return Err(unsupported());
    }
    Ok(())
}
