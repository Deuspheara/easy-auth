-- A contact address must never implicitly select weaker authentication authority.
ALTER TABLE auth_users ALTER COLUMN email DROP NOT NULL;
ALTER TABLE auth_users ALTER COLUMN email_verified_at DROP NOT NULL;
ALTER TABLE auth_users ADD COLUMN display_name text
    CHECK (display_name IS NULL OR (octet_length(display_name) BETWEEN 1 AND 256
        AND display_name !~ '[[:cntrl:]]' AND btrim(display_name) <> ''));
ALTER TABLE auth_users ADD COLUMN authentication_policy text NOT NULL DEFAULT 'mailbox'
    CHECK (authentication_policy IN ('mailbox','passkey_required'));
ALTER TABLE auth_users ADD CONSTRAINT auth_users_verified_mailbox
    CHECK ((email IS NULL) = (email_verified_at IS NULL));
ALTER TABLE auth_users ADD CONSTRAINT auth_users_email_free_policy
    CHECK (email IS NOT NULL OR (authentication_policy='passkey_required' AND display_name IS NOT NULL));

ALTER TABLE auth_rate_buckets DROP CONSTRAINT auth_rate_buckets_dimension_check;
ALTER TABLE auth_rate_buckets ADD CONSTRAINT auth_rate_buckets_dimension_check
    CHECK (dimension IN ('email','source','password_email','password_source',
        'sensitive_user','sensitive_source',
        'passkey_enroll_user','passkey_enroll_source','passkey_finish_user','passkey_finish_source',
        'passkey_auth_start_browser','passkey_auth_start_source',
        'passkey_auth_finish_browser','passkey_auth_finish_source'));
