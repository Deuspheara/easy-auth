use uuid::Uuid;

/// Closed lifecycle facts: identifiers only, with no strings or secret-bearing context.
/// Only the repository transaction that commits a verified operation records its event.
#[derive(Debug)]
pub enum AuditEvent {
    OidcIdentityLinked {
        user_id: Uuid,
        actor_session_id: Uuid,
        identity_id: Uuid,
    },
    OidcIdentityUnlinked {
        user_id: Uuid,
        actor_session_id: Uuid,
        identity_id: Uuid,
    },
    IssuerNativeCredential(super::IssuerNativeCredentialEvent),
    IssuerAuthorized {
        user_id: Uuid,
        actor_session_id: Uuid,
        client_id: Uuid,
        authorization_id: Uuid,
    },
    IssuerCodeRedeemed {
        user_id: Uuid,
        actor_session_id: Uuid,
        client_id: Uuid,
        authorization_id: Uuid,
    },
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
