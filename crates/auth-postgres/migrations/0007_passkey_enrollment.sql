CREATE TABLE auth_passkeys (
    realm_id uuid NOT NULL,
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    rp_id text NOT NULL CHECK (octet_length(rp_id) BETWEEN 1 AND 253),
    credential_id bytea NOT NULL CHECK (octet_length(credential_id) BETWEEN 1 AND 1024),
    credential bytea NOT NULL CHECK (octet_length(credential) BETWEEN 1 AND 65536),
    label text NOT NULL CHECK (octet_length(label) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    PRIMARY KEY (realm_id,id),
    UNIQUE (rp_id,credential_id),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE
);
CREATE INDEX auth_passkey_owner ON auth_passkeys(realm_id,user_id,rp_id);
CREATE TABLE auth_passkey_enrollments (
    realm_id uuid NOT NULL,
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    rp_id text NOT NULL CHECK (octet_length(rp_id) BETWEEN 1 AND 253),
    label text NOT NULL CHECK (octet_length(label) BETWEEN 1 AND 256),
    private_state bytea NOT NULL CHECK (octet_length(private_state) BETWEEN 1 AND 32768),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '2 minutes'),
    PRIMARY KEY (realm_id,id),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id,session_id,user_id) REFERENCES auth_sessions(realm_id,id,user_id) ON DELETE CASCADE
);
CREATE INDEX auth_passkey_pending_owner ON auth_passkey_enrollments(realm_id,user_id);
CREATE INDEX auth_passkey_pending_expiry ON auth_passkey_enrollments(expires_at);
ALTER TABLE auth_rate_buckets DROP CONSTRAINT auth_rate_buckets_dimension_check;
ALTER TABLE auth_rate_buckets ADD CONSTRAINT auth_rate_buckets_dimension_check
    CHECK (dimension IN ('email','source','password_email','password_source',
        'passkey_enroll_user','passkey_enroll_source','passkey_finish_user','passkey_finish_source'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','account_deleted',
        'all_sessions_revoked','passkey_enrolled'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind='password_enrolled' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind='password_reset' AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
