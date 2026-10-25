-- Explicit offline-capable native registrations cannot be interpreted by older
-- loaders as an ordinary online client. Existing rows and revisions are unchanged.
ALTER TABLE auth_issuer_clients DROP CONSTRAINT auth_issuer_redirect_profile;
ALTER TABLE auth_issuer_clients ADD CONSTRAINT auth_issuer_redirect_profile CHECK (
    (redirect_profile = 'web_exact' AND sector NOT LIKE 'urn:easy-auth:native-client:%')
    OR (redirect_profile IN ('native_loopback', 'native_refresh_loopback')
        AND authentication = 'none'
        AND sector = 'urn:easy-auth:native-client:' || id::text)
);

-- Configuration only: this table grants no consent, code, refresh or local session.
-- Initial deny survives replacement; every use must recheck the full current
-- client and policy snapshots in client-before-policy lock order.
CREATE TABLE auth_issuer_native_refresh_policies (
    realm_id uuid NOT NULL,
    issuer text NOT NULL CHECK (length(issuer) BETWEEN 1 AND 2048),
    client_id uuid NOT NULL,
    revision uuid NOT NULL CHECK (revision <> '00000000-0000-0000-0000-000000000000'),
    client_revision uuid NOT NULL,
    lifetime_seconds integer NOT NULL CHECK (lifetime_seconds BETWEEN 1 AND 604800),
    idle_seconds integer NOT NULL CHECK (idle_seconds BETWEEN 1 AND 86400 AND idle_seconds <= lifetime_seconds),
    enabled boolean NOT NULL DEFAULT false,
    PRIMARY KEY (realm_id, issuer, client_id),
    FOREIGN KEY (realm_id, client_id) REFERENCES auth_issuer_clients(realm_id,id) ON DELETE CASCADE
);
