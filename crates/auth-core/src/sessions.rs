use uuid::Uuid;

/// Public session metadata. Neither the bearer secret nor its verifier belongs here.
#[derive(Debug, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: Uuid,
    pub current: bool,
    pub created_at_ms: i64,
    pub last_seen_at_ms: i64,
    pub expires_at_ms: i64,
    pub idle_expires_at_ms: i64,
    pub authenticated_at_ms: Option<i64>,
}

#[derive(Debug)]
pub struct SessionPage {
    pub sessions: Vec<SessionInfo>,
    pub next: Option<Uuid>,
}
