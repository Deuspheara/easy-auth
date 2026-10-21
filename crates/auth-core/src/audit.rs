use uuid::Uuid;

/// Closed lifecycle facts: identifiers only, with no strings or secret-bearing context.
/// Only the repository transaction that commits a verified operation records its event.
#[derive(Debug)]
pub enum AuditEvent {
    SamlAuthenticated {
        user_id: Uuid,
        session_id: Uuid,
    },
    OidcAuthenticated {
        user_id: Uuid,
        session_id: Uuid,
    },
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
    PasskeyRenamed {
        passkey_id: Uuid,
        user_id: Uuid,
        actor_session_id: Uuid,
    },
    PasskeyRemoved {
        passkey_id: Uuid,
        user_id: Uuid,
        actor_session_id: Uuid,
    },
    PasskeyRecovered {
        user_id: Uuid,
        claim_id: Uuid,
        session_id: Uuid,
    },
    PasskeyRecoveryStarted {
        user_id: Uuid,
        claim_id: Uuid,
    },
    PasskeyRecoveryCancelled {
        user_id: Uuid,
        claim_id: Uuid,
        actor_session_id: Option<Uuid>,
    },
    PasskeyRecoveryConfigured {
        user_id: Uuid,
        actor_session_id: Uuid,
    },
    PasskeyAuthenticated {
        user_id: Uuid,
        session_id: Uuid,
    },
    PasskeySignedUp {
        user_id: Uuid,
        session_id: Uuid,
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
    EmailAttached {
        user_id: Uuid,
        actor_session_id: Uuid,
        session_id: Uuid,
    },
    /// Deletion keeps the fact, after erasing subject/session attribution.
    AccountDeleted,
}

impl AuditEvent {
    pub fn recovery_claim_id(&self) -> Option<Uuid> {
        match self {
            Self::PasskeyRecovered { claim_id, .. }
            | Self::PasskeyRecoveryStarted { claim_id, .. }
            | Self::PasskeyRecoveryCancelled { claim_id, .. } => Some(*claim_id),
            _ => None,
        }
    }

    pub fn passkey_id(&self) -> Option<Uuid> {
        match self {
            Self::PasskeyRenamed { passkey_id, .. } | Self::PasskeyRemoved { passkey_id, .. } => {
                Some(*passkey_id)
            }
            _ => None,
        }
    }

    pub fn kind(&self) -> &'static str {
        match self {
            Self::SamlAuthenticated { .. } => "saml_authenticated",
            Self::OidcAuthenticated { .. } => "oidc_authenticated",
            Self::EmailAuthenticated { .. } => "email_authenticated",
            Self::PasswordAuthenticated { .. } => "password_authenticated",
            Self::PasswordEnrolled { .. } => "password_enrolled",
            Self::PasskeyEnrolled { .. } => "passkey_enrolled",
            Self::PasskeyRenamed { .. } => "passkey_renamed",
            Self::PasskeyRemoved { .. } => "passkey_removed",
            Self::PasskeyRecovered { .. } => "passkey_recovered",
            Self::PasskeyRecoveryStarted { .. } => "passkey_recovery_started",
            Self::PasskeyRecoveryCancelled { .. } => "passkey_recovery_cancelled",
            Self::PasskeyRecoveryConfigured { .. } => "passkey_recovery_configured",
            Self::PasskeyAuthenticated { .. } => "passkey_authenticated",
            Self::PasskeySignedUp { .. } => "passkey_signed_up",
            Self::PasswordReset { .. } => "password_reset",
            Self::SessionRevoked { .. } => "session_revoked",
            Self::AllSessionsRevoked { .. } => "all_sessions_revoked",
            Self::EmailChanged { .. } => "email_changed",
            Self::EmailAttached { .. } => "email_attached",
            Self::AccountDeleted => "account_deleted",
        }
    }
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::EmailAuthenticated { user_id, .. }
            | Self::OidcAuthenticated { user_id, .. }
            | Self::SamlAuthenticated { user_id, .. }
            | Self::PasswordAuthenticated { user_id, .. }
            | Self::PasswordEnrolled { user_id, .. }
            | Self::PasskeyEnrolled { user_id, .. }
            | Self::PasskeyRenamed { user_id, .. }
            | Self::PasskeyRemoved { user_id, .. }
            | Self::PasskeyRecoveryConfigured { user_id, .. }
            | Self::PasskeyRecovered { user_id, .. }
            | Self::PasskeyRecoveryStarted { user_id, .. }
            | Self::PasskeyRecoveryCancelled { user_id, .. }
            | Self::PasskeyAuthenticated { user_id, .. }
            | Self::PasskeySignedUp { user_id, .. }
            | Self::PasswordReset { user_id }
            | Self::SessionRevoked { user_id, .. }
            | Self::AllSessionsRevoked { user_id, .. }
            | Self::EmailChanged { user_id, .. } => Some(*user_id),
            Self::EmailAttached { user_id, .. } => Some(*user_id),
            Self::AccountDeleted => None,
        }
    }
    pub fn actor_session_id(&self) -> Option<Uuid> {
        match self {
            Self::PasskeyRecoveryCancelled {
                actor_session_id, ..
            } => *actor_session_id,
            Self::PasswordEnrolled {
                actor_session_id, ..
            }
            | Self::PasskeyEnrolled {
                actor_session_id, ..
            }
            | Self::PasskeyRenamed {
                actor_session_id, ..
            }
            | Self::PasskeyRemoved {
                actor_session_id, ..
            }
            | Self::PasskeyRecoveryConfigured {
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
            }
            | Self::EmailAttached {
                actor_session_id, ..
            } => Some(*actor_session_id),
            Self::EmailAuthenticated { .. }
            | Self::OidcAuthenticated { .. }
            | Self::SamlAuthenticated { .. }
            | Self::PasskeyAuthenticated { .. }
            | Self::PasskeySignedUp { .. }
            | Self::PasskeyRecovered { .. }
            | Self::PasskeyRecoveryStarted { .. }
            | Self::PasswordAuthenticated { .. }
            | Self::PasswordReset { .. }
            | Self::AccountDeleted => None,
        }
    }
    pub fn session_id(&self) -> Option<Uuid> {
        match self {
            Self::EmailAuthenticated { session_id, .. }
            | Self::OidcAuthenticated { session_id, .. }
            | Self::SamlAuthenticated { session_id, .. }
            | Self::PasskeyAuthenticated { session_id, .. }
            | Self::PasskeySignedUp { session_id, .. }
            | Self::PasskeyRecovered { session_id, .. }
            | Self::PasswordAuthenticated { session_id, .. }
            | Self::PasswordEnrolled { session_id, .. }
            | Self::EmailAttached { session_id, .. }
            | Self::SessionRevoked { session_id, .. } => Some(*session_id),
            Self::PasswordReset { .. }
            | Self::PasskeyEnrolled { .. }
            | Self::PasskeyRenamed { .. }
            | Self::PasskeyRemoved { .. }
            | Self::PasskeyRecoveryConfigured { .. }
            | Self::PasskeyRecoveryStarted { .. }
            | Self::PasskeyRecoveryCancelled { .. }
            | Self::AllSessionsRevoked { .. }
            | Self::EmailChanged { .. }
            | Self::AccountDeleted => None,
        }
    }
}
