CREATE TABLE auth_password_credentials (
    realm_id uuid NOT NULL,
    user_id uuid NOT NULL,
    password_hash text NOT NULL CHECK (octet_length(password_hash) <= 256),
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, user_id),
    FOREIGN KEY (realm_id, user_id) REFERENCES auth_users(realm_id, id) ON DELETE CASCADE
);
ALTER TABLE auth_rate_buckets DROP CONSTRAINT auth_rate_buckets_dimension_check;
ALTER TABLE auth_rate_buckets ADD CONSTRAINT auth_rate_buckets_dimension_check
    CHECK (dimension IN ('email', 'source', 'password_email', 'password_source'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated', 'session_revoked', 'password_enrolled', 'password_authenticated'));
