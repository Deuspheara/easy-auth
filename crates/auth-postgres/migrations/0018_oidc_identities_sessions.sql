ALTER TABLE auth_users DROP CONSTRAINT auth_users_authentication_policy_check;
ALTER TABLE auth_users ADD CONSTRAINT auth_users_authentication_policy_check
    CHECK (authentication_policy IN ('mailbox','passkey_required','provider_required'));
ALTER TABLE auth_users DROP CONSTRAINT auth_users_email_free_policy;
ALTER TABLE auth_users ADD CONSTRAINT auth_users_email_free_policy
    CHECK (email IS NOT NULL OR (authentication_policy IN ('passkey_required','provider_required') AND display_name IS NOT NULL));

CREATE TABLE auth_oidc_identities (
    realm_id uuid NOT NULL,
    id uuid NOT NULL,
    connection_id uuid NOT NULL,
    client_id uuid NOT NULL,
    issuer text COLLATE "C" NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    subject text COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 255),
    user_id uuid NOT NULL,
    PRIMARY KEY (realm_id,id),
    UNIQUE (realm_id,id,user_id),
    UNIQUE (realm_id,connection_id,client_id,issuer,subject),
    FOREIGN KEY (realm_id,connection_id,client_id) REFERENCES auth_oauth_connections(realm_id,id,client_id),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE
);
CREATE INDEX auth_oidc_identities_owner ON auth_oidc_identities(realm_id,user_id);

ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_authentication_method_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_authentication_method_check
    CHECK (authentication_method IN ('legacy_unknown','email','password','passkey','oidc'));
ALTER TABLE auth_sessions ADD COLUMN oidc_identity_id uuid, ADD COLUMN oidc_revision uuid;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_oidc_source CHECK (
    (authentication_method='oidc' AND oidc_identity_id IS NOT NULL AND oidc_revision IS NOT NULL)
    OR (authentication_method<>'oidc' AND oidc_identity_id IS NULL AND oidc_revision IS NULL)
);
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_oidc_owner
    FOREIGN KEY (realm_id,oidc_identity_id,user_id) REFERENCES auth_oidc_identities(realm_id,id,user_id) ON DELETE CASCADE;

-- Established SHA-256 over an unambiguous scoped tuple; not a credential verifier.
CREATE FUNCTION auth_oidc_subject_key(realm uuid, connection uuid, client uuid, issuer text, subject text)
RETURNS bytea LANGUAGE sql STABLE STRICT AS $$
    SELECT sha256(convert_to(jsonb_build_array(realm::text,connection::text,client::text,issuer,subject)::text,'UTF8'))
$$;
CREATE TABLE auth_oidc_deleted_subjects (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    subject_hash bytea NOT NULL CHECK (octet_length(subject_hash)=32),
    blocked_until timestamptz NOT NULL CHECK (isfinite(blocked_until)),
    PRIMARY KEY (realm_id,subject_hash)
);
CREATE INDEX auth_oidc_deleted_subjects_expiry ON auth_oidc_deleted_subjects(realm_id,blocked_until);
-- All original OAuth proofs expire within five minutes. Keep no raw subject or
-- erased owner reference. Deletion never takes configuration/advisory locks.
CREATE FUNCTION auth_oidc_remember_deleted_subjects() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO auth_oidc_deleted_subjects(realm_id,subject_hash,blocked_until)
    SELECT realm_id,auth_oidc_subject_key(realm_id,connection_id,client_id,issuer,subject),clock_timestamp()+interval '5 minutes'
    FROM auth_oidc_identities WHERE realm_id=OLD.realm_id AND user_id=OLD.id
    ON CONFLICT (realm_id,subject_hash) DO UPDATE SET
      blocked_until=greatest(auth_oidc_deleted_subjects.blocked_until,EXCLUDED.blocked_until);
    RETURN OLD;
END $$;
CREATE TRIGGER auth_oidc_remember_deleted_subjects BEFORE DELETE ON auth_users
FOR EACH ROW EXECUTE FUNCTION auth_oidc_remember_deleted_subjects();

ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','email_attached','account_deleted',
        'all_sessions_revoked','passkey_enrolled','passkey_authenticated','passkey_signed_up',
        'passkey_renamed','passkey_removed','passkey_recovery_configured',
        'passkey_recovery_started','passkey_recovery_cancelled','passkey_recovered','oidc_authenticated'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated','passkey_signed_up','passkey_recovered','oidc_authenticated') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind IN ('password_enrolled','email_attached') AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind IN ('password_reset','passkey_recovery_started') AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind='passkey_recovery_cancelled' AND session_id IS NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled','passkey_renamed','passkey_removed','passkey_recovery_configured') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
