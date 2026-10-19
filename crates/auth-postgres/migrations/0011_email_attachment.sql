CREATE TABLE auth_email_attachments (
    realm_id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    email text NOT NULL CHECK (email=lower(email)),
    token_hash bytea NOT NULL CHECK (octet_length(token_hash)=32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '5 minutes'),
    PRIMARY KEY (realm_id,user_id),
    UNIQUE (realm_id,token_hash),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id,session_id,user_id) REFERENCES auth_sessions(realm_id,id,user_id) ON DELETE CASCADE
);
CREATE INDEX auth_email_attachment_expiry ON auth_email_attachments(expires_at);

ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','email_attached','account_deleted',
        'all_sessions_revoked','passkey_enrolled','passkey_authenticated','passkey_signed_up'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated','passkey_signed_up') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind IN ('password_enrolled','email_attached') AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind='password_reset' AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
