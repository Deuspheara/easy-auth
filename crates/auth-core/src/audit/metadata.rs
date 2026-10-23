use super::AuditEvent;
use uuid::Uuid;

impl AuditEvent {
    pub fn issuer_client_id(&self) -> Option<Uuid> {
        match self {
            Self::IssuerAuthorized { client_id, .. }
            | Self::IssuerCodeRedeemed { client_id, .. } => Some(*client_id),
            _ => None,
        }
    }
    pub fn issuer_authorization_id(&self) -> Option<Uuid> {
        match self {
            Self::IssuerAuthorized {
                authorization_id, ..
            }
            | Self::IssuerCodeRedeemed {
                authorization_id, ..
            } => Some(*authorization_id),
            _ => None,
        }
    }
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
            Self::IssuerAuthorized { .. } => "issuer_authorized",
            Self::IssuerCodeRedeemed { .. } => "issuer_code_redeemed",
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
}
