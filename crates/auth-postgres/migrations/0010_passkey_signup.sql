CREATE TABLE auth_passkey_signups (
    realm_id uuid NOT NULL REFERENCES auth_realms(id) ON DELETE CASCADE,
    id uuid NOT NULL,
    prospective_user uuid NOT NULL,
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    rp_id text NOT NULL CHECK (octet_length(rp_id) BETWEEN 1 AND 253),
    display_name text NOT NULL CHECK (octet_length(display_name) BETWEEN 1 AND 256
        AND display_name !~ '[[:cntrl:]]' AND btrim(display_name)<>''),
    stage text NOT NULL CHECK (stage IN ('registration','assertion')),
    registration_state bytea CHECK (octet_length(registration_state) BETWEEN 1 AND 32768),
    authentication_state bytea CHECK (octet_length(authentication_state) BETWEEN 1 AND 1048576),
    candidate_id bytea CHECK (octet_length(candidate_id) BETWEEN 1 AND 1024),
    candidate bytea CHECK (octet_length(candidate) BETWEEN 1 AND 65536),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '2 minutes'),
    PRIMARY KEY (realm_id,id),
    UNIQUE (realm_id,prospective_user),
    CHECK ((stage='registration' AND registration_state IS NOT NULL
            AND authentication_state IS NULL AND candidate_id IS NULL AND candidate IS NULL)
        OR (stage='assertion' AND registration_state IS NULL
            AND authentication_state IS NOT NULL AND candidate_id IS NOT NULL AND candidate IS NOT NULL))
);
CREATE INDEX auth_passkey_signup_browser ON auth_passkey_signups(realm_id,browser_hash);
CREATE INDEX auth_passkey_signup_expiry ON auth_passkey_signups(realm_id,expires_at);

ALTER TABLE auth_rate_buckets DROP CONSTRAINT auth_rate_buckets_dimension_check;
ALTER TABLE auth_rate_buckets ADD CONSTRAINT auth_rate_buckets_dimension_check
    CHECK (dimension IN ('email','source','password_email','password_source',
        'sensitive_user','sensitive_source',
        'passkey_enroll_user','passkey_enroll_source','passkey_finish_user','passkey_finish_source',
        'passkey_auth_start_browser','passkey_auth_start_source',
        'passkey_auth_finish_browser','passkey_auth_finish_source',
        'passkey_signup_start_browser','passkey_signup_start_source',
        'passkey_signup_finish_browser','passkey_signup_finish_source'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','account_deleted',
        'all_sessions_revoked','passkey_enrolled','passkey_authenticated','passkey_signed_up'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated','passkey_signed_up') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind='password_enrolled' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind='password_reset' AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
