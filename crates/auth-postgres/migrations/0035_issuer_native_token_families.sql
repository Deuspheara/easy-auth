-- Native offline grants are separate from the original short online access row.
ALTER TABLE auth_issuer_native_consents ADD CONSTRAINT auth_issuer_native_grant_tuple UNIQUE
    (realm_id,authorization_id,issuer,client_id,client_revision,policy_revision,user_id,session_id,
     lifetime_seconds,idle_seconds,prepared_at_us,approved_at_us,source_absolute_cap_us,grant_expires_at_us);
CREATE TABLE auth_issuer_native_families (
    realm_id uuid NOT NULL,
    issuer text COLLATE "C" NOT NULL,
    id uuid NOT NULL CHECK(id<>'00000000-0000-0000-0000-000000000000'),
    authorization_id uuid NOT NULL,
    client_id uuid NOT NULL,
    client_revision uuid NOT NULL,
    policy_revision uuid NOT NULL CHECK(policy_revision<>'00000000-0000-0000-0000-000000000000'),
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    subject uuid NOT NULL,
    authentication_method text NOT NULL CHECK(authentication_method IN ('email','password','passkey','oidc','saml')),
    authenticated_at_us bigint NOT NULL CHECK(authenticated_at_us>=0),
    lifetime_seconds integer NOT NULL CHECK(lifetime_seconds BETWEEN 1 AND 604800),
    idle_seconds integer NOT NULL CHECK(idle_seconds BETWEEN 1 AND 86400 AND idle_seconds<=lifetime_seconds),
    prepared_at_us bigint NOT NULL CHECK(prepared_at_us>=authenticated_at_us),
    approved_at_us bigint NOT NULL CHECK(approved_at_us>=prepared_at_us),
    source_absolute_cap_us bigint NOT NULL CHECK(source_absolute_cap_us>prepared_at_us),
    created_at_us bigint NOT NULL CHECK(created_at_us>=approved_at_us),
    expires_at_us bigint NOT NULL CHECK(expires_at_us>created_at_us AND expires_at_us<=source_absolute_cap_us
        AND expires_at_us<=prepared_at_us+lifetime_seconds::bigint*1000000),
    idle_until_us bigint NOT NULL CHECK(idle_until_us>created_at_us AND idle_until_us<=expires_at_us),
    generation bigint NOT NULL DEFAULT 0 CHECK(generation BETWEEN 0 AND 10000),
    revoked_at_us bigint CHECK(revoked_at_us>=created_at_us),
    PRIMARY KEY(realm_id,id),
    UNIQUE(realm_id,authorization_id),
    UNIQUE(realm_id,id,authorization_id,client_id,user_id),
    UNIQUE(realm_id,issuer,id,authorization_id,client_id,user_id),
    UNIQUE(realm_id,issuer,id,authorization_id,client_id,user_id,session_id,subject),
    FOREIGN KEY(realm_id,authorization_id,issuer,client_id,client_revision,policy_revision,user_id,session_id,
        lifetime_seconds,idle_seconds,prepared_at_us,approved_at_us,source_absolute_cap_us,expires_at_us)
        REFERENCES auth_issuer_native_consents(realm_id,authorization_id,issuer,client_id,client_revision,policy_revision,user_id,session_id,
            lifetime_seconds,idle_seconds,prepared_at_us,approved_at_us,source_absolute_cap_us,grant_expires_at_us) ON DELETE CASCADE,
    FOREIGN KEY(realm_id,authorization_id,issuer,client_id,user_id,session_id,subject)
        REFERENCES auth_issuer_authorizations(realm_id,id,issuer,client_id,user_id,session_id,subject) ON DELETE CASCADE
);
CREATE INDEX auth_issuer_native_family_owner ON auth_issuer_native_families(realm_id,client_id,user_id);
CREATE TABLE auth_issuer_native_refresh_tokens (
    realm_id uuid NOT NULL,
    issuer text COLLATE "C" NOT NULL,
    family_id uuid NOT NULL,
    authorization_id uuid NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    generation bigint NOT NULL CHECK(generation BETWEEN 0 AND 10000),
    token_hash bytea NOT NULL CHECK(octet_length(token_hash)=32),
    issued_at_us bigint NOT NULL CHECK(issued_at_us>=0),
    spent_at_us bigint CHECK(spent_at_us>=issued_at_us),
    PRIMARY KEY(realm_id,family_id,generation),
    UNIQUE(realm_id,token_hash),
    FOREIGN KEY(realm_id,issuer,family_id,authorization_id,client_id,user_id)
        REFERENCES auth_issuer_native_families(realm_id,issuer,id,authorization_id,client_id,user_id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX auth_issuer_native_unspent_refresh ON auth_issuer_native_refresh_tokens(realm_id,family_id) WHERE spent_at_us IS NULL;

ALTER TABLE auth_issuer_authorizations ADD CONSTRAINT auth_issuer_native_marker UNIQUE(realm_id,id,native_refresh);
ALTER TABLE auth_issuer_access_tokens
    DROP CONSTRAINT auth_issuer_access_tokens_realm_id_authorization_id_key,
    ADD COLUMN native_refresh boolean NOT NULL DEFAULT false,
    ADD COLUMN native_family_id uuid,
    ADD COLUMN native_generation bigint,
    ADD CONSTRAINT auth_issuer_access_native_generation CHECK (
        (NOT native_refresh AND native_family_id IS NULL AND native_generation IS NULL)
        OR (native_refresh AND native_family_id IS NOT NULL AND native_generation IS NOT NULL AND native_generation BETWEEN 0 AND 10000)),
    ADD CONSTRAINT auth_issuer_access_native_marker FOREIGN KEY(realm_id,authorization_id,native_refresh)
        REFERENCES auth_issuer_authorizations(realm_id,id,native_refresh),
    ADD CONSTRAINT auth_issuer_access_native_owner FOREIGN KEY(realm_id,issuer,native_family_id,authorization_id,client_id,user_id,session_id,subject)
        REFERENCES auth_issuer_native_families(realm_id,issuer,id,authorization_id,client_id,user_id,session_id,subject) ON DELETE CASCADE;
CREATE UNIQUE INDEX auth_issuer_online_access_once ON auth_issuer_access_tokens(realm_id,authorization_id) WHERE native_family_id IS NULL;
CREATE UNIQUE INDEX auth_issuer_native_access_generation ON auth_issuer_access_tokens(realm_id,native_family_id,native_generation) WHERE native_family_id IS NOT NULL;

ALTER TABLE auth_audit
    ADD COLUMN issuer_family_id uuid,
    ADD COLUMN issuer_generation bigint,
    ADD COLUMN issuer_credential_kind text,
    ADD CONSTRAINT auth_audit_native_owner FOREIGN KEY(realm_id,issuer_family_id,issuer_authorization_id,issuer_client_id,user_id)
        REFERENCES auth_issuer_native_families(realm_id,id,authorization_id,client_id,user_id),
    ADD CONSTRAINT auth_audit_native_generation FOREIGN KEY(realm_id,issuer_family_id,issuer_generation)
        REFERENCES auth_issuer_native_refresh_tokens(realm_id,family_id,generation);
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_issuer_metadata;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_issuer_metadata CHECK (
    (subject_erased AND issuer_client_id IS NULL AND issuer_authorization_id IS NULL)
    OR (NOT subject_erased AND (
        (kind IN ('issuer_authorized','issuer_code_redeemed','issuer_native_created','issuer_native_rotated','issuer_native_reuse_revoked','issuer_native_revoked') AND schema_version=1
            AND issuer_client_id IS NOT NULL AND issuer_authorization_id IS NOT NULL)
        OR (kind NOT IN ('issuer_authorized','issuer_code_redeemed','issuer_native_created','issuer_native_rotated','issuer_native_reuse_revoked','issuer_native_revoked')
            AND issuer_client_id IS NULL AND issuer_authorization_id IS NULL)
    ))
);
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_issuer_version;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_issuer_version CHECK (
    kind NOT IN ('issuer_authorized','issuer_code_redeemed','issuer_native_created','issuer_native_rotated','issuer_native_reuse_revoked','issuer_native_revoked') OR schema_version=1
);
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check CHECK (kind IN (
    'email_authenticated','session_revoked','password_enrolled','password_authenticated','password_reset',
    'email_changed','email_attached','account_deleted','all_sessions_revoked','passkey_enrolled',
    'passkey_authenticated','passkey_signed_up','passkey_renamed','passkey_removed','passkey_recovery_configured',
    'passkey_recovery_started','passkey_recovery_cancelled','passkey_recovered','oidc_authenticated',
    'saml_authenticated','issuer_authorized','issuer_code_redeemed','issuer_native_created','issuer_native_rotated','issuer_native_reuse_revoked','issuer_native_revoked'));
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
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled','passkey_renamed','passkey_removed','passkey_recovery_configured','issuer_authorized','issuer_code_redeemed') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);

ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_native_metadata CHECK (
    (subject_erased AND issuer_family_id IS NULL AND issuer_generation IS NULL AND issuer_credential_kind IS NULL)
    OR (NOT subject_erased AND (
        (kind IN ('issuer_native_created','issuer_native_rotated','issuer_native_reuse_revoked','issuer_native_revoked')
            AND schema_version=1 AND issuer_family_id IS NOT NULL AND issuer_generation IS NOT NULL AND issuer_generation BETWEEN 0 AND 10000 AND issuer_credential_kind IS NOT NULL
            AND actor_session_id IS NULL AND session_id IS NULL
            AND ((kind='issuer_native_created' AND issuer_credential_kind='authorization_code')
                OR (kind IN ('issuer_native_rotated','issuer_native_reuse_revoked') AND issuer_credential_kind='refresh_token')
                OR (kind='issuer_native_revoked' AND issuer_credential_kind IN ('refresh_token','access_token'))))
        OR (kind NOT IN ('issuer_native_created','issuer_native_rotated','issuer_native_reuse_revoked','issuer_native_revoked')
            AND issuer_family_id IS NULL AND issuer_generation IS NULL AND issuer_credential_kind IS NULL)
    ))
);
-- Existing feature-disabled account erasure must also deidentify newer native
-- credential facts. This trigger only removes references; it creates no authority.
CREATE FUNCTION auth_erase_native_audit_references() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.subject_erased THEN
        NEW.issuer_family_id=NULL;
        NEW.issuer_generation=NULL;
        NEW.issuer_credential_kind=NULL;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER auth_erase_native_audit_references BEFORE UPDATE ON auth_audit
    FOR EACH ROW EXECUTE FUNCTION auth_erase_native_audit_references();
