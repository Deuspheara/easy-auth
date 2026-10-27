-- Explicit links are distinct from JIT identities. Installing this schema grants
-- no fallback to historical or provider-only owners and enables no HTTP route.
ALTER TABLE auth_oidc_identities ADD COLUMN explicitly_linked boolean NOT NULL DEFAULT false;

-- Preserve original method/revision/history for audit-referenced sessions after
-- unlink. Detachment is permitted only after revocation; active-source validation
-- still requires an actual identity and rejects even an improperly unrevoked row.
ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_oidc_source;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_oidc_source CHECK (
    (authentication_method='oidc' AND oidc_revision IS NOT NULL
        AND (oidc_identity_id IS NOT NULL OR revoked_at IS NOT NULL))
    OR (authentication_method<>'oidc' AND oidc_identity_id IS NULL AND oidc_revision IS NULL)
);

ALTER TABLE auth_audit ADD COLUMN oidc_identity_id uuid;
-- The removed identity UUID is finite audit metadata, not an active foreign key
-- or subject/credential. Actor ownership retains the existing composite FK.
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check CHECK (kind IN (
    'email_authenticated','session_revoked','password_enrolled','password_authenticated','password_reset',
    'email_changed','email_attached','account_deleted','all_sessions_revoked','passkey_enrolled',
    'passkey_authenticated','passkey_signed_up','passkey_renamed','passkey_removed','passkey_recovery_configured',
    'passkey_recovery_started','passkey_recovery_cancelled','passkey_recovered','oidc_authenticated',
    'saml_authenticated','issuer_authorized','issuer_code_redeemed','issuer_native_created','issuer_native_rotated','issuer_native_reuse_revoked','issuer_native_revoked','oidc_identity_linked','oidc_identity_unlinked'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated','passkey_signed_up','passkey_recovered','oidc_authenticated','saml_authenticated') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind IN ('password_enrolled','email_attached') AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind IN ('issuer_native_created','issuer_native_rotated','issuer_native_reuse_revoked','issuer_native_revoked') AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind IN ('password_reset','passkey_recovery_started') AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind='passkey_recovery_cancelled' AND session_id IS NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled','passkey_renamed','passkey_removed','passkey_recovery_configured','issuer_authorized','issuer_code_redeemed','oidc_identity_linked','oidc_identity_unlinked') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);

ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_oidc_link_metadata CHECK (
    (subject_erased AND oidc_identity_id IS NULL)
    OR (NOT subject_erased AND (
        (kind IN ('oidc_identity_linked','oidc_identity_unlinked') AND schema_version=1
            AND oidc_identity_id IS NOT NULL AND actor_session_id IS NOT NULL AND session_id IS NULL)
        OR (kind NOT IN ('oidc_identity_linked','oidc_identity_unlinked') AND oidc_identity_id IS NULL)
    ))
);
-- Feature-disabled account erasure must remove newer references too, without
-- requiring its SQL statements to name future feature columns.
CREATE FUNCTION auth_erase_oidc_link_audit_references() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.subject_erased THEN NEW.oidc_identity_id=NULL; END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER auth_erase_oidc_link_audit_references BEFORE UPDATE ON auth_audit
    FOR EACH ROW EXECUTE FUNCTION auth_erase_oidc_link_audit_references();

ALTER TABLE auth_security_notifications DROP CONSTRAINT auth_security_notifications_kind_check;
ALTER TABLE auth_security_notifications ADD CONSTRAINT auth_security_notifications_kind_check
    CHECK (kind IN ('password_reset','email_changed','account_deleted','passkeys_changed',
        'passkey_recovery_changed','passkey_recovery_started','passkey_recovery_cancelled',
        'passkey_recovery_completed','providers_changed'));
