use super::AuditEvent;
use uuid::Uuid;

impl AuditEvent {
    pub fn user_id(&self) -> Option<Uuid> {
        match self {
            Self::IssuerAuthorized { user_id, .. }
            | Self::IssuerCodeRedeemed { user_id, .. }
            | Self::EmailAuthenticated { user_id, .. }
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
            Self::IssuerAuthorized {
                actor_session_id, ..
            }
            | Self::IssuerCodeRedeemed {
                actor_session_id, ..
            }
            | Self::PasswordEnrolled {
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
            Self::IssuerAuthorized { .. }
            | Self::IssuerCodeRedeemed { .. }
            | Self::PasswordReset { .. }
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
