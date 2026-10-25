use crate::{IssuerAuthority, IssuerClientRegistration, IssuerTokenError, IssuerTokenResult};
use uuid::Uuid;

/// Trusted repository facts, not an identity/session proof. Local owner/session,
/// secret hashes, nonce and original code are deliberately absent.
pub struct IssuerAccessData {
    pub realm: Uuid,
    pub issuer: String,
    pub client: Uuid,
    pub subject: Uuid,
    pub issued_at_us: i64,
    pub expires_at_us: i64,
    pub checked_at_us: i64,
}

/// Validated active-token metadata for an authenticated consuming client. No
/// Serialize/Clone or local owner projection; HTTP defines its closed wire DTO.
pub struct IssuerActiveAccess(IssuerAccessData);
impl IssuerActiveAccess {
    pub(super) fn from_repository(
        data: IssuerAccessData,
        authority: &IssuerAuthority,
        client: &IssuerClientRegistration,
    ) -> IssuerTokenResult<Self> {
        if data.realm != authority.realm()
            || data.issuer != authority.issuer()
            || data.client != client.client()
            || data.subject.is_nil()
            || data.issued_at_us < 0
            || data.checked_at_us < data.issued_at_us
            || data.checked_at_us >= data.expires_at_us
            || data.expires_at_us.saturating_sub(data.issued_at_us)
                > crate::ISSUER_ID_TOKEN_LIFETIME_SECONDS * 1_000_000
        {
            return Err(IssuerTokenError::Unavailable);
        }
        Ok(Self(data))
    }
    pub fn issuer(&self) -> &str {
        &self.0.issuer
    }
    pub fn client(&self) -> Uuid {
        self.0.client
    }
    pub fn subject(&self) -> Uuid {
        self.0.subject
    }
    pub fn issued_at_us(&self) -> i64 {
        self.0.issued_at_us
    }
    pub fn expires_at_us(&self) -> i64 {
        self.0.expires_at_us
    }
    pub fn checked_at_us(&self) -> i64 {
        self.0.checked_at_us
    }
}
