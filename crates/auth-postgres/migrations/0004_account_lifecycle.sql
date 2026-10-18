-- Existing sessions lack trustworthy authentication-time provenance; require fresh login for sensitive actions.
ALTER TABLE auth_sessions ADD COLUMN authenticated_at timestamptz NOT NULL DEFAULT '-infinity';
ALTER TABLE auth_sessions ALTER COLUMN authenticated_at SET DEFAULT clock_timestamp();
ALTER TABLE auth_sessions ADD CONSTRAINT auth_session_owner UNIQUE (realm_id,id,user_id);
CREATE TABLE auth_email_changes (
    realm_id uuid NOT NULL,
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    old_email text NOT NULL,
    new_email text NOT NULL,
    old_hash bytea NOT NULL CHECK (octet_length(old_hash)=32),
    new_hash bytea NOT NULL CHECK (octet_length(new_hash)=32 AND new_hash<>old_hash),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    old_confirmed boolean NOT NULL DEFAULT false,
    new_confirmed boolean NOT NULL DEFAULT false,
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '5 minutes'),
    PRIMARY KEY (realm_id,id),
    UNIQUE (realm_id,old_hash), UNIQUE (realm_id,new_hash),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id,session_id,user_id) REFERENCES auth_sessions(realm_id,id,user_id) ON DELETE CASCADE
);
CREATE TABLE auth_account_deletions (
    realm_id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    email text NOT NULL,
    token_hash bytea NOT NULL CHECK (octet_length(token_hash)=32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    expires_at timestamptz NOT NULL DEFAULT (clock_timestamp()+interval '5 minutes'),
    PRIMARY KEY (realm_id,token_hash),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id,session_id,user_id) REFERENCES auth_sessions(realm_id,id,user_id) ON DELETE CASCADE
);
ALTER TABLE auth_password_reset_notifications RENAME TO auth_security_notifications;
ALTER TABLE auth_security_notifications ADD COLUMN kind text NOT NULL DEFAULT 'password_reset'
    CHECK (kind IN ('password_reset','email_changed','account_deleted'));
ALTER TABLE auth_security_notifications ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE auth_security_notifications ADD CONSTRAINT auth_notice_subject
    CHECK ((kind='account_deleted' AND user_id IS NULL) OR (kind<>'account_deleted' AND user_id IS NOT NULL));
ALTER TABLE auth_audit ALTER COLUMN user_id DROP NOT NULL;
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled','password_authenticated','password_reset','email_changed','account_deleted'));
ALTER TABLE auth_security_notifications ADD CONSTRAINT auth_security_notice_realm
    FOREIGN KEY (realm_id) REFERENCES auth_realms(id);
