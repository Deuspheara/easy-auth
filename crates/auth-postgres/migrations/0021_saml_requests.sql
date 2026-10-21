-- Gated outgoing SAML registration/request state only. No ACS or identity grant.
CREATE TABLE auth_saml_registrations (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    id uuid NOT NULL,
    client_id uuid NOT NULL,
    revision uuid NOT NULL,
    sp_entity text NOT NULL CHECK (octet_length(sp_entity) BETWEEN 1 AND 1024),
    idp_entity text NOT NULL CHECK (octet_length(idp_entity) BETWEEN 1 AND 1024),
    sso_url text NOT NULL CHECK (octet_length(sso_url) BETWEEN 1 AND 2048),
    acs_url text NOT NULL CHECK (octet_length(acs_url) BETWEEN 1 AND 2048),
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (realm_id, id, client_id)
);

CREATE TABLE auth_saml_requests (
    realm_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    client_id uuid NOT NULL,
    revision uuid NOT NULL,
    request_id text NOT NULL CHECK (request_id ~ '^_[A-Za-z0-9_-]{1,127}$'),
    relay_hash bytea NOT NULL CHECK (octet_length(relay_hash) = 32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    expires_at timestamptz NOT NULL,
    PRIMARY KEY (realm_id, connection_id, client_id, request_id),
    UNIQUE (realm_id, relay_hash),
    FOREIGN KEY (realm_id, connection_id, client_id)
        REFERENCES auth_saml_registrations(realm_id, id, client_id) ON DELETE CASCADE,
    CHECK (isfinite(created_at) AND isfinite(expires_at) AND expires_at > created_at)
);
CREATE INDEX auth_saml_requests_expiry ON auth_saml_requests (realm_id, expires_at);
