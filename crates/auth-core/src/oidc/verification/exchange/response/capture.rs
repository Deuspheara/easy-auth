use super::OidcTokenResponse;
use crate::{Error, OidcIdToken, Result};
use zeroize::Zeroizing;

const MAX_ACCESS_TOKEN_SECONDS: u64 = 24 * 60 * 60;
pub(in crate::oidc) struct AppleGrantTokenReply {
    pub id_token: OidcIdToken,
    pub token: Zeroizing<String>,
    pub access_expires_us: Option<i64>,
}
impl OidcTokenResponse {
    pub(in crate::oidc) fn apple_grant(self, requested_us: i64) -> Result<AppleGrantTokenReply> {
        let mut wire = self.success()?;
        let id_token = OidcIdToken::parse(std::mem::take(&mut wire.id_token))?;
        let (token, access_expires_us) = if let Some(refresh) = wire.refresh_token.take() {
            (refresh, None)
        } else {
            let seconds = wire
                ._expires_in
                .filter(|v| *v > 0 && *v <= MAX_ACCESS_TOKEN_SECONDS)
                .ok_or(Error::Unavailable)?;
            if requested_us < 0 {
                return Err(Error::Unavailable);
            }
            let expires = requested_us
                .checked_add(
                    i64::try_from(seconds)
                        .map_err(|_| Error::Unavailable)?
                        .checked_mul(1_000_000)
                        .ok_or(Error::Unavailable)?,
                )
                .ok_or(Error::Unavailable)?;
            (std::mem::take(&mut wire.access_token), Some(expires))
        };
        Ok(AppleGrantTokenReply {
            id_token,
            token: Zeroizing::new(token),
            access_expires_us,
        })
    }
}
