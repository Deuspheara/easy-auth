-- Outbound consent/code state is separate from inbound federation and sessions.
-- Only verifier digests are stored for private browser/handle/code credentials.
ALTER TABLE auth_issuer_subjects ADD CONSTRAINT auth_issuer_subject_exact_owner
    UNIQUE (realm_id,sector,user_id,subject);
CREATE TABLE auth_issuer_authorizations (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    issuer text COLLATE "C" NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    client_id uuid NOT NULL,
    client_revision uuid NOT NULL,
    sector text COLLATE "C" NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    authentication_method text NOT NULL CHECK (authentication_method IN ('email','password','passkey','oidc','saml')),
    authenticated_at_us bigint NOT NULL CHECK (authenticated_at_us >= 0),
    session_cap_us bigint NOT NULL CHECK (session_cap_us > authenticated_at_us),
    handle_hash bytea NOT NULL CHECK (octet_length(handle_hash)=32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    redirect_uri text COLLATE "C" NOT NULL CHECK (octet_length(redirect_uri) BETWEEN 1 AND 2048),
    state text COLLATE "C" CHECK (octet_length(state) BETWEEN 1 AND 1024),
    nonce text COLLATE "C" CHECK (octet_length(nonce) BETWEEN 1 AND 1024),
    pkce_challenge bytea CHECK (octet_length(pkce_challenge)=32),
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','consumed','expired')),
    subject uuid,
    code_hash bytea CHECK (octet_length(code_hash)=32),
    created_at_us bigint NOT NULL CHECK (created_at_us >= authenticated_at_us),
    expires_at_us bigint NOT NULL CHECK (expires_at_us > created_at_us AND expires_at_us <= session_cap_us),
    approved_at_us bigint,
    code_expires_at_us bigint,
    consumed_at_us bigint,
    PRIMARY KEY (realm_id,id),
    UNIQUE (realm_id,handle_hash),
    UNIQUE (realm_id,id,client_id,user_id,session_id),
    FOREIGN KEY (realm_id,client_id) REFERENCES auth_issuer_clients(realm_id,id),
    FOREIGN KEY (realm_id,sector) REFERENCES auth_issuer_sectors(realm_id,host),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id,session_id,user_id) REFERENCES auth_sessions(realm_id,id,user_id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id,sector,user_id,subject) REFERENCES auth_issuer_subjects(realm_id,sector,user_id,subject) ON DELETE CASCADE,
    CHECK ((status IN ('pending','approved') AND state IS NOT NULL AND nonce IS NOT NULL AND pkce_challenge IS NOT NULL)
        OR (status IN ('consumed','expired') AND state IS NULL AND nonce IS NULL AND pkce_challenge IS NULL)),
    CHECK ((status='pending' AND code_hash IS NULL AND subject IS NULL AND approved_at_us IS NULL AND code_expires_at_us IS NULL)
        OR (status<>'pending' AND code_hash IS NOT NULL AND subject IS NOT NULL
            AND approved_at_us IS NOT NULL AND code_expires_at_us IS NOT NULL AND approved_at_us >= created_at_us
            AND code_expires_at_us > approved_at_us AND code_expires_at_us <= expires_at_us)),
    CHECK ((status='consumed' AND consumed_at_us IS NOT NULL AND consumed_at_us >= approved_at_us AND consumed_at_us < code_expires_at_us)
        OR (status<>'consumed' AND consumed_at_us IS NULL))
);
CREATE UNIQUE INDEX auth_issuer_code_hash ON auth_issuer_authorizations(realm_id,code_hash) WHERE code_hash IS NOT NULL;
CREATE INDEX auth_issuer_pending_owner ON auth_issuer_authorizations(realm_id,user_id,status);

CREATE TABLE auth_issuer_token_admission (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    source_hash bytea NOT NULL CHECK (octet_length(source_hash)=32),
    window_id bigint NOT NULL CHECK (window_id >= 0),
    attempts bigint NOT NULL CHECK (attempts > 0),
    PRIMARY KEY (realm_id,source_hash,window_id)
);

ALTER TABLE auth_audit ADD COLUMN issuer_client_id uuid, ADD COLUMN issuer_authorization_id uuid;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_issuer_owner
    FOREIGN KEY (realm_id,issuer_authorization_id,issuer_client_id,user_id,actor_session_id)
    REFERENCES auth_issuer_authorizations(realm_id,id,client_id,user_id,session_id);
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_issuer_metadata CHECK (
    (subject_erased AND issuer_client_id IS NULL AND issuer_authorization_id IS NULL)
    OR (NOT subject_erased AND (
        (kind IN ('issuer_authorized','issuer_code_redeemed') AND schema_version=1
            AND issuer_client_id IS NOT NULL AND issuer_authorization_id IS NOT NULL)
        OR (kind NOT IN ('issuer_authorized','issuer_code_redeemed')
            AND issuer_client_id IS NULL AND issuer_authorization_id IS NULL)
    ))
);
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_issuer_version CHECK (
    kind NOT IN ('issuer_authorized','issuer_code_redeemed') OR schema_version=1
);
ALTER TABLE auth_audit DROP CONSTRAINT auth_audit_kind_check;
ALTER TABLE auth_audit ADD CONSTRAINT auth_audit_kind_check CHECK (kind IN (
    'email_authenticated','session_revoked','password_enrolled','password_authenticated','password_reset',
    'email_changed','email_attached','account_deleted','all_sessions_revoked','passkey_enrolled',
    'passkey_authenticated','passkey_signed_up','passkey_renamed','passkey_removed','passkey_recovery_configured',
    'passkey_recovery_started','passkey_recovery_cancelled','passkey_recovered','oidc_authenticated',
    'saml_authenticated','issuer_authorized','issuer_code_redeemed'));
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
        OR (kind IN ('all_sessions_revoked','email_changed','passkey_enrolled','passkey_renamed','passkey_removed','passkey_recovery_configured','issuer_authorized','issuer_code_redeemed') AND actor_session_id IS NOT NULL AND session_id IS NULL)
    ))
);
