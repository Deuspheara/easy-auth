-- Metadata concurrency is independent of WebAuthn's assertion/counter snapshots.
ALTER TABLE auth_passkeys ADD COLUMN management_version uuid NOT NULL DEFAULT gen_random_uuid();
ALTER TABLE auth_audit ADD COLUMN passkey_id uuid;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_passkey_target CHECK (
    (subject_erased AND passkey_id IS NULL)
    OR (NOT subject_erased AND (
        (kind IN ('passkey_renamed','passkey_removed') AND passkey_id IS NOT NULL)
        OR (kind NOT IN ('passkey_renamed','passkey_removed') AND passkey_id IS NULL)
    ))
);
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','email_attached','account_deleted',
        'all_sessions_revoked','passkey_enrolled','passkey_authenticated','passkey_signed_up',
        'passkey_renamed','passkey_removed'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated','passkey_signed_up') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind IN ('password_enrolled','email_attached') AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind='password_reset' AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled','passkey_renamed','passkey_removed') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
ALTER TABLE auth_security_notifications DROP CONSTRAINT auth_security_notifications_kind_check;
ALTER TABLE auth_security_notifications ADD CONSTRAINT auth_security_notifications_kind_check
    CHECK (kind IN ('password_reset','email_changed','account_deleted','passkeys_changed'));
