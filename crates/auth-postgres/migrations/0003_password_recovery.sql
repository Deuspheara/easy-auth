ALTER TABLE auth_password_credentials ADD COLUMN version uuid NOT NULL DEFAULT gen_random_uuid();
CREATE TABLE auth_password_resets (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    token_hash bytea NOT NULL CHECK (octet_length(token_hash)=32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    email text NOT NULL,
    credential_version uuid,
    expires_at timestamptz NOT NULL DEFAULT (now()+interval '10 minutes'),
    PRIMARY KEY (realm_id, token_hash)
);
CREATE INDEX auth_password_reset_email ON auth_password_resets(realm_id,email);
CREATE INDEX auth_password_reset_expiry ON auth_password_resets(expires_at);
CREATE INDEX auth_email_challenge_email ON auth_email_challenges(realm_id,email);
CREATE TABLE auth_password_reset_notifications (
    realm_id uuid NOT NULL,
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    recipient text NOT NULL CHECK (octet_length(recipient)<=254),
    created_at timestamptz NOT NULL DEFAULT now(),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts BETWEEN 0 AND 8),
    lease_id uuid,
    lease_until timestamptz,
    PRIMARY KEY (realm_id,id),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE
);
CREATE INDEX auth_password_notification_due ON auth_password_reset_notifications(realm_id,next_attempt_at) WHERE attempts<8;
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled','password_authenticated','password_reset'));
