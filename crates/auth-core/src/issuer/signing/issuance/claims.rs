use crate::{
    IssuerAuthority, IssuerClientRegistration, IssuerGrantData, IssuerTokenError, IssuerTokenResult,
};
use serde::Serialize;
use zeroize::Zeroizing;

#[derive(Serialize)]
struct IdClaims<'a> {
    iss: &'a str,
    sub: String,
    aud: String,
    nonce: &'a str,
    iat: i64,
    exp: i64,
    auth_time: i64,
}
pub(super) fn payload(
    authority: &IssuerAuthority,
    grant: &IssuerGrantData,
    client: &IssuerClientRegistration,
    expires_at_us: i64,
) -> IssuerTokenResult<Zeroizing<Vec<u8>>> {
    let claims = IdClaims {
        iss: authority.issuer(),
        sub: grant.subject.to_string(),
        aud: client.client().to_string(),
        nonce: &grant.nonce,
        iat: grant.issued_at_us / 1_000_000,
        exp: expires_at_us / 1_000_000,
        auth_time: grant.authenticated_at_us / 1_000_000,
    };
    serde_json::to_vec(&claims)
        .map(Zeroizing::new)
        .map_err(|_| IssuerTokenError::Unavailable)
}
