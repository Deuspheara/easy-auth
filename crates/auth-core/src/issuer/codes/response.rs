use super::{IssuerAuthority, IssuerAuthorizationDestination, IssuerAuthorizationReturn, request};
use crate::{Error, Result, Secret};
use url::form_urlencoded::Serializer;
use zeroize::Zeroizing;

pub(super) fn destination(
    authority: &IssuerAuthority,
    data: IssuerAuthorizationDestination,
    code: Option<&Secret>,
) -> Result<IssuerAuthorizationReturn> {
    if data.client.realm() != authority.realm() {
        return Err(Error::Unavailable);
    }
    request::return_uri(&data.client, &data.redirect_uri).map_err(|_| Error::Unavailable)?;
    request::correlation(&data.state).map_err(|_| Error::Unavailable)?;
    let mut query = Serializer::new(String::new());
    if let Some(code) = code {
        query.append_pair("code", code.expose());
    } else {
        query.append_pair("error", "access_denied");
    }
    query
        .append_pair("state", &data.state)
        .append_pair("iss", authority.issuer());
    // Append encoded response fields without reserializing the original URI:
    // keep fixed query spelling and an explicitly supplied native :80 intact.
    let delimiter = if data.redirect_uri.contains('?') {
        '&'
    } else {
        '?'
    };
    Ok(IssuerAuthorizationReturn(Zeroizing::new(format!(
        "{}{delimiter}{}",
        data.redirect_uri,
        query.finish()
    ))))
}
