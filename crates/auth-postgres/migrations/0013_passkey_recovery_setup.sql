-- Experimental saved-code configuration. No recovery authentication is enabled.
CREATE TABLE auth_passkey_recovery_codes (
    realm_id uuid NOT NULL,
    user_id uuid NOT NULL,
    rp_id text NOT NULL CHECK (octet_length(rp_id) BETWEEN 1 AND 253),
    version uuid NOT NULL,
    code_hash bytea NOT NULL CHECK (octet_length(code_hash)=32),
    confirmed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (realm_id,user_id,rp_id),
    UNIQUE (realm_id,rp_id,code_hash),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE
);
CREATE TABLE auth_passkey_recovery_setups (
    realm_id uuid NOT NULL,
    user_id uuid NOT NULL,
    rp_id text NOT NULL CHECK (octet_length(rp_id) BETWEEN 1 AND 253),
    id uuid NOT NULL,
    session_id uuid NOT NULL,
    code_hash bytea NOT NULL CHECK (octet_length(code_hash)=32),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '10 minutes'),
    PRIMARY KEY (realm_id,user_id,rp_id),
    UNIQUE (realm_id,id),
    FOREIGN KEY (realm_id,session_id,user_id) REFERENCES auth_sessions(realm_id,id,user_id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE
);
CREATE INDEX auth_passkey_recovery_setup_expiry ON auth_passkey_recovery_setups(expires_at);

ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','email_attached','account_deleted',
        'all_sessions_revoked','passkey_enrolled','passkey_authenticated','passkey_signed_up',
        'passkey_renamed','passkey_removed','passkey_recovery_configured'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated','passkey_signed_up') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind IN ('password_enrolled','email_attached') AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind='password_reset' AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled','passkey_renamed','passkey_removed','passkey_recovery_configured') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
ALTER TABLE auth_security_notifications DROP CONSTRAINT auth_security_notifications_kind_check;
ALTER TABLE auth_security_notifications ADD CONSTRAINT auth_security_notifications_kind_check
    CHECK (kind IN ('password_reset','email_changed','account_deleted','passkeys_changed','passkey_recovery_changed'));
