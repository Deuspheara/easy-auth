use uuid::Uuid;

/// Closed credential lifecycle facts, not proof that a caller owns a credential.
/// Record only after the exact scoped hash/family is locked by its transaction.
#[derive(Debug)]
pub struct IssuerNativeCredentialEvent {
    pub user_id: Uuid,
    pub client_id: Uuid,
    pub authorization_id: Uuid,
    pub family_id: Uuid,
    pub generation: i64,
    pub action: IssuerNativeCredentialAction,
    pub credential: IssuerNativeCredentialKind,
}
#[derive(Clone, Copy, Debug)]
pub enum IssuerNativeCredentialAction {
    Created,
    Rotated,
    ReuseRevoked,
    Revoked,
}
impl IssuerNativeCredentialAction {
    pub fn kind(self) -> &'static str {
        match self {
            Self::Created => "issuer_native_created",
            Self::Rotated => "issuer_native_rotated",
            Self::ReuseRevoked => "issuer_native_reuse_revoked",
            Self::Revoked => "issuer_native_revoked",
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub enum IssuerNativeCredentialKind {
    AuthorizationCode,
    RefreshToken,
    AccessToken,
}
impl IssuerNativeCredentialKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::AccessToken => "access_token",
        }
    }
}
