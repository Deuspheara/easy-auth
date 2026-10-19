use serde::Serialize;
use uuid::Uuid;

/// Public management metadata. No WebAuthn ID, credential encoding or owner selector.
#[derive(Debug, Serialize)]
pub struct PasskeyInfo {
    pub id: Uuid,
    pub version: Uuid,
    pub label: String,
    pub created_at_ms: i64,
    pub last_used_at_ms: Option<i64>,
}
