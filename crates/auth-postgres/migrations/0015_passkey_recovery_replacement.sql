ALTER TABLE auth_passkey_recovery_claims ADD COLUMN completed_at timestamptz
    CHECK (completed_at IS NULL OR (isfinite(completed_at) AND completed_at>=created_at AND cancelled_at IS NULL));

CREATE TABLE auth_passkey_recovery_replacements (
    realm_id uuid NOT NULL,
    claim_id uuid NOT NULL,
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    stage text NOT NULL DEFAULT 'registration' CHECK (stage IN ('registration','assertion')),
    registration_state bytea CHECK (octet_length(registration_state)<=65536),
    authentication_state bytea CHECK (octet_length(authentication_state)<=65536),
    candidate_id bytea CHECK (octet_length(candidate_id) BETWEEN 1 AND 1024),
    candidate bytea CHECK (octet_length(candidate)<=65536),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
    PRIMARY KEY (realm_id,claim_id),
    UNIQUE (realm_id,id),
    FOREIGN KEY (realm_id,claim_id,user_id) REFERENCES auth_passkey_recovery_claims(realm_id,id,user_id) ON DELETE CASCADE,
    CHECK ((stage='registration' AND registration_state IS NOT NULL AND authentication_state IS NULL AND candidate_id IS NULL AND candidate IS NULL)
        OR (stage='assertion' AND registration_state IS NULL AND authentication_state IS NOT NULL AND candidate_id IS NOT NULL AND candidate IS NOT NULL))
);

ALTER TABLE auth_security_notifications DROP CONSTRAINT auth_security_notifications_kind_check;
ALTER TABLE auth_security_notifications ADD CONSTRAINT auth_security_notifications_kind_check
    CHECK (kind IN ('password_reset','email_changed','account_deleted','passkeys_changed',
        'passkey_recovery_changed','passkey_recovery_started','passkey_recovery_cancelled','passkey_recovery_completed'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_recovery_target;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_recovery_target CHECK (
    (subject_erased AND recovery_claim_id IS NULL)
    OR (NOT subject_erased AND (
        (kind IN ('passkey_recovery_started','passkey_recovery_cancelled','passkey_recovered') AND recovery_claim_id IS NOT NULL)
        OR (kind NOT IN ('passkey_recovery_started','passkey_recovery_cancelled','passkey_recovered') AND recovery_claim_id IS NULL)
    ))
);
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','email_attached','account_deleted',
        'all_sessions_revoked','passkey_enrolled','passkey_authenticated','passkey_signed_up',
        'passkey_renamed','passkey_removed','passkey_recovery_configured',
        'passkey_recovery_started','passkey_recovery_cancelled','passkey_recovered'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated','passkey_signed_up','passkey_recovered') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind IN ('password_enrolled','email_attached') AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind IN ('password_reset','passkey_recovery_started') AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind='passkey_recovery_cancelled' AND session_id IS NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled','passkey_renamed','passkey_removed','passkey_recovery_configured') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
