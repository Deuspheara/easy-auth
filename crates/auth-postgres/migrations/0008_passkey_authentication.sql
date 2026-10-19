-- Old authentication methods cannot be inferred safely, including password-enrollment rotations.
ALTER TABLE auth_sessions ADD COLUMN authentication_method text NOT NULL DEFAULT 'legacy_unknown'
    CHECK (authentication_method IN ('legacy_unknown','email','password','passkey'));

CREATE TABLE auth_passkey_authentications (
    realm_id uuid NOT NULL REFERENCES auth_realms(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    user_id uuid,
    purpose text NOT NULL CHECK (purpose IN ('account_bound','discoverable')),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    rp_id text NOT NULL CHECK (octet_length(rp_id) BETWEEN 1 AND 253),
    private_state bytea NOT NULL CHECK (octet_length(private_state) BETWEEN 1 AND 1048576),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '2 minutes'),
    PRIMARY KEY (realm_id,id),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE,
    CHECK ((purpose='account_bound' AND user_id IS NOT NULL)
        OR (purpose='discoverable' AND user_id IS NULL))
);
CREATE INDEX auth_passkey_authentication_browser ON auth_passkey_authentications(realm_id,browser_hash);
CREATE INDEX auth_passkey_authentication_owner ON auth_passkey_authentications(realm_id,user_id);
CREATE INDEX auth_passkey_authentication_expiry ON auth_passkey_authentications(expires_at);
ALTER TABLE auth_passkeys ADD COLUMN last_used_at timestamptz;

ALTER TABLE auth_rate_buckets DROP CONSTRAINT auth_rate_buckets_dimension_check;
ALTER TABLE auth_rate_buckets ADD CONSTRAINT auth_rate_buckets_dimension_check
    CHECK (dimension IN ('email','source','password_email','password_source',
        'passkey_enroll_user','passkey_enroll_source','passkey_finish_user','passkey_finish_source',
        'passkey_auth_start_browser','passkey_auth_start_source',
        'passkey_auth_finish_browser','passkey_auth_finish_source'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','account_deleted',
        'all_sessions_revoked','passkey_enrolled','passkey_authenticated'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind='password_enrolled' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind='password_reset' AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
