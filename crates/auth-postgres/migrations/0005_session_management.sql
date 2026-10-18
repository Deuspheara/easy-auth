CREATE INDEX auth_active_session_page ON auth_sessions(realm_id,user_id,id)
    WHERE revoked_at IS NULL;
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','account_deleted',
        'all_sessions_revoked'));
