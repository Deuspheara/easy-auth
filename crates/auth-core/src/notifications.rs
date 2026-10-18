use uuid::Uuid;

/// Non-secret, purpose-specific delivery work. Never exposed through the HTTP API.
pub enum SecurityNoticeKind {
    PasswordReset,
    EmailChanged,
    AccountDeleted,
}
pub struct SecurityNotice {
    pub kind: SecurityNoticeKind,
    pub id: Uuid,
    pub lease: Uuid,
    pub recipient: String,
}
