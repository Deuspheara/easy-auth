use auth_core::IssuerActiveAccess;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub(in crate::issuer_web) enum TokenIntrospectionResponse {
    Active(ActiveToken),
    Inactive(InactiveToken),
}
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(in crate::issuer_web) struct InactiveToken {
    pub active: bool,
}
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(in crate::issuer_web) struct ActiveToken {
    pub active: bool,
    pub iss: String,
    pub client_id: Uuid,
    pub aud: Uuid,
    pub sub: Uuid,
    pub iat: i64,
    pub exp: i64,
    pub token_type: &'static str,
    pub scope: &'static str,
}
impl From<IssuerActiveAccess> for ActiveToken {
    fn from(token: IssuerActiveAccess) -> Self {
        Self::from_access(&token, "openid")
    }
}
impl ActiveToken {
    fn from_access(token: &IssuerActiveAccess, scope: &'static str) -> Self {
        Self {
            active: true,
            iss: token.issuer().to_owned(),
            client_id: token.client(),
            aud: token.client(),
            sub: token.subject(),
            iat: token.issued_at_us() / 1_000_000,
            exp: token.expires_at_us() / 1_000_000,
            token_type: "Bearer",
            scope,
        }
    }
}

#[cfg(feature = "issuer-native-web")]
impl From<auth_core::IssuerNativeActiveAccess> for ActiveToken {
    fn from(token: auth_core::IssuerNativeActiveAccess) -> Self {
        Self::from_access(token.access(), auth_core::ISSUER_NATIVE_SCOPE)
    }
}
