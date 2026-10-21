-- Established SHA-256 of the complete exact namespace; not credential verification.
CREATE FUNCTION auth_saml_subject_key(realm uuid, connection uuid, client uuid, idp text, sp text, subject text)
RETURNS bytea LANGUAGE sql STABLE STRICT AS $$
    SELECT sha256(convert_to(jsonb_build_array(realm::text,connection::text,client::text,idp,sp,subject)::text,'UTF8'))
$$;

-- Gated SAML sign-in: exact persistent-subject ownership and durable replay.
CREATE TABLE auth_saml_identities (
    realm_id uuid NOT NULL,
    id uuid NOT NULL,
    connection_id uuid NOT NULL,
    client_id uuid NOT NULL,
    idp_entity text COLLATE "C" NOT NULL CHECK (octet_length(idp_entity) BETWEEN 1 AND 1024),
    sp_entity text COLLATE "C" NOT NULL CHECK (octet_length(sp_entity) BETWEEN 1 AND 1024),
    subject text COLLATE "C" NOT NULL CHECK (octet_length(subject) BETWEEN 1 AND 1024 AND char_length(subject)<=256),
    user_id uuid NOT NULL,
    subject_hash bytea NOT NULL CHECK (octet_length(subject_hash)=32),
    CHECK (subject_hash=auth_saml_subject_key(realm_id,connection_id,client_id,idp_entity,sp_entity,subject)),
    PRIMARY KEY (realm_id,id),
    UNIQUE (realm_id,id,user_id),
    -- A complete valid URI/Unicode tuple can exceed PostgreSQL's btree entry
    -- size. Bound the unique index to SHA-256, and compare full fields on lookup.
    UNIQUE (realm_id,subject_hash),
    FOREIGN KEY (realm_id,connection_id,client_id) REFERENCES auth_saml_registrations(realm_id,id,client_id),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE
);
CREATE INDEX auth_saml_identities_owner ON auth_saml_identities(realm_id,user_id);

-- Neither revision, client nor erased user is part of the replay namespace.
-- Configuration rotation or owner deletion must not reset accepted IDs.
CREATE TABLE auth_saml_replays (
    realm_id uuid NOT NULL REFERENCES auth_realms(id) ON DELETE CASCADE,
    connection_id uuid NOT NULL,
    identifier_hash bytea NOT NULL CHECK (octet_length(identifier_hash)=32),
    kind text NOT NULL CHECK (kind IN ('response','assertion')),
    retain_until timestamptz NOT NULL CHECK (isfinite(retain_until)),
    PRIMARY KEY (realm_id,connection_id,identifier_hash)
);
CREATE INDEX auth_saml_replays_expiry ON auth_saml_replays(realm_id,connection_id,retain_until);

ALTER TABLE auth_sessions DROP CONSTRAINT auth_sessions_authentication_method_check;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_authentication_method_check
    CHECK (authentication_method IN ('legacy_unknown','email','password','passkey','oidc','saml'));
ALTER TABLE auth_sessions ADD COLUMN saml_identity_id uuid, ADD COLUMN saml_revision uuid;
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_saml_source CHECK (
    (authentication_method='saml' AND saml_identity_id IS NOT NULL AND saml_revision IS NOT NULL)
    OR (authentication_method<>'saml' AND saml_identity_id IS NULL AND saml_revision IS NULL)
);
ALTER TABLE auth_sessions ADD CONSTRAINT auth_sessions_saml_owner
    FOREIGN KEY (realm_id,saml_identity_id,user_id) REFERENCES auth_saml_identities(realm_id,id,user_id) ON DELETE CASCADE;

CREATE TABLE auth_saml_deleted_subjects (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    subject_hash bytea NOT NULL CHECK (octet_length(subject_hash)=32),
    blocked_until timestamptz NOT NULL CHECK (isfinite(blocked_until)),
    PRIMARY KEY (realm_id,subject_hash)
);
CREATE INDEX auth_saml_deleted_subjects_expiry ON auth_saml_deleted_subjects(realm_id,blocked_until);
CREATE FUNCTION auth_saml_remember_deleted_subjects() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO auth_saml_deleted_subjects(realm_id,subject_hash,blocked_until)
    SELECT realm_id,auth_saml_subject_key(realm_id,connection_id,client_id,idp_entity,sp_entity,subject),clock_timestamp()+interval '5 minutes'
    FROM auth_saml_identities WHERE realm_id=OLD.realm_id AND user_id=OLD.id
    ON CONFLICT (realm_id,subject_hash) DO UPDATE SET
      blocked_until=greatest(auth_saml_deleted_subjects.blocked_until,EXCLUDED.blocked_until);
    RETURN OLD;
END $$;
CREATE TRIGGER auth_saml_remember_deleted_subjects BEFORE DELETE ON auth_users
FOR EACH ROW EXECUTE FUNCTION auth_saml_remember_deleted_subjects();

ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check
    CHECK (kind IN ('email_authenticated','session_revoked','password_enrolled',
        'password_authenticated','password_reset','email_changed','email_attached','account_deleted',
        'all_sessions_revoked','passkey_enrolled','passkey_authenticated','passkey_signed_up',
        'passkey_renamed','passkey_removed','passkey_recovery_configured',
        'passkey_recovery_started','passkey_recovery_cancelled','passkey_recovered','oidc_authenticated','saml_authenticated'));
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_event_shape;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_event_shape CHECK (
    (schema_version=0 AND actor_session_id IS NULL AND session_id IS NULL)
    OR (schema_version=1 AND (
        subject_erased
        OR (kind IN ('email_authenticated','password_authenticated','passkey_authenticated','passkey_signed_up','passkey_recovered','oidc_authenticated','saml_authenticated') AND actor_session_id IS NULL AND session_id IS NOT NULL)
        OR (kind IN ('password_enrolled','email_attached') AND actor_session_id IS NOT NULL AND session_id IS NOT NULL AND actor_session_id<>session_id)
        OR (kind IN ('password_reset','passkey_recovery_started') AND actor_session_id IS NULL AND session_id IS NULL)
        OR (kind='session_revoked' AND actor_session_id IS NOT NULL AND session_id IS NOT NULL)
        OR (kind='passkey_recovery_cancelled' AND session_id IS NULL)
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled','passkey_renamed','passkey_removed','passkey_recovery_configured') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
