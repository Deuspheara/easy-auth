use uuid::Uuid;

/// Metadata only, never authentication or authority to bind a key. Completion
/// must independently lock/revalidate the exact claim, generation and deadlines.
#[derive(Debug)]
pub struct PasskeyRecoveryClaimInfo {
    pub id: Uuid,
    pub expires_at_ms: i64,
    pub not_before_ms: Option<i64>,
    pub notification_required: bool,
    pub ready: bool,
}
