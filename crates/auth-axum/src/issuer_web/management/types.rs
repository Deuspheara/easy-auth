use auth_core::IssuerActiveAccess;
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

#[derive(Serialize, ToSchema)]
#[serde(untagged)]
pub(super) enum TokenIntrospectionResponse {
    Active(ActiveToken),
    Inactive(InactiveToken),
}
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct InactiveToken {
    pub active: bool,
}
#[derive(Serialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub(super) struct ActiveToken {
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
        Self {
            active: true,
            iss: token.issuer().to_owned(),
            client_id: token.client(),
            aud: token.client(),
            sub: token.subject(),
            iat: token.issued_at_us() / 1_000_000,
            exp: token.expires_at_us() / 1_000_000,
            token_type: "Bearer",
            scope: "openid",
        }
    }
}
