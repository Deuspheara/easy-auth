use uuid::Uuid;

/// Closed lifecycle facts: identifiers only, with no strings or secret-bearing context.
/// Only the repository transaction that commits a verified operation records its event.
#[derive(Debug)]
pub enum AuditEvent {
    EmailAuthenticated {
        user_id: Uuid,
        session_id: Uuid,
    },
    PasswordAuthenticated {
        user_id: Uuid,
        session_id: Uuid,
    },
    PasswordEnrolled {
        user_id: Uuid,
        actor_session_id: Uuid,
        session_id: Uuid,
    },
    PasskeyEnrolled {
        user_id: Uuid,
        actor_session_id: Uuid,
    },
    PasswordReset {
        user_id: Uuid,
    },
    SessionRevoked {
        user_id: Uuid,
        actor_session_id: Uuid,
        session_id: Uuid,
    },
    AllSessionsRevoked {
        user_id: Uuid,
        actor_session_id: Uuid,
    },
    EmailChanged {
        user_id: Uuid,
        actor_session_id: Uuid,
    },
    /// Deletion keeps the fact, after erasing subject/session attribution.
    AccountDeleted,
}

impl AuditEvent {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::EmailAuthenticated { .. } => "email_authenticated",
            Self::PasswordAuthenticated { .. } => "password_authenticated",
            Self::PasswordEnrolled { .. } => "password_enrolled",
            Self::PasskeyEnrolled { .. } => "passkey_enrolled",
            Self::PasswordReset { .. } => "password_reset",
            Self::SessionRevoked { .. } => "session_revoked",
            Self::AllSessionsRevoked { .. } => "all_sessions_revoked",
            Self::EmailChanged { .. } => "email_changed",
            Self::AccountDeleted => "account_deleted",
        }
    }
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::EmailAuthenticated { user_id, .. }
            | Self::PasswordAuthenticated { user_id, .. }
            | Self::PasswordEnrolled { user_id, .. }
            | Self::PasskeyEnrolled { user_id, .. }
            | Self::PasswordReset { user_id }
            | Self::SessionRevoked { user_id, .. }
            | Self::AllSessionsRevoked { user_id, .. }
            | Self::EmailChanged { user_id, .. } => Some(*user_id),
            Self::AccountDeleted => None,
        }
    }
    pub fn actor_session_id(&self) -> Option<Uuid> {
        match self {
            Self::PasswordEnrolled {
                actor_session_id, ..
            }
            | Self::PasskeyEnrolled {
                actor_session_id, ..
            }
            | Self::SessionRevoked {
                actor_session_id, ..
            }
            | Self::AllSessionsRevoked {
                actor_session_id, ..
            }
            | Self::EmailChanged {
                actor_session_id, ..
            } => Some(*actor_session_id),
            Self::EmailAuthenticated { .. }
            | Self::PasswordAuthenticated { .. }
            | Self::PasswordReset { .. }
            | Self::AccountDeleted => None,
        }
    }
    pub fn session_id(&self) -> Option<Uuid> {
        match self {
            Self::EmailAuthenticated { session_id, .. }
            | Self::PasswordAuthenticated { session_id, .. }
            | Self::PasswordEnrolled { session_id, .. }
            | Self::SessionRevoked { session_id, .. } => Some(*session_id),
            Self::PasswordReset { .. }
            | Self::PasskeyEnrolled { .. }
            | Self::AllSessionsRevoked { .. }
            | Self::EmailChanged { .. }
            | Self::AccountDeleted => None,
        }
    }
}
