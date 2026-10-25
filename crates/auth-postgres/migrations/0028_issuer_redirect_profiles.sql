-- Preserve every existing web registration, revision, credential and subject.
-- Native interface ports are request-specific; the later code retains its exact
-- return URI. A shared loopback address is never a shared pairwise sector.
ALTER TABLE auth_issuer_clients
    ADD COLUMN redirect_profile text NOT NULL DEFAULT 'web_exact',
    ADD CONSTRAINT auth_issuer_redirect_profile CHECK (
        (redirect_profile = 'web_exact' AND sector NOT LIKE 'urn:easy-auth:native-client:%')
        OR (redirect_profile = 'native_loopback' AND authentication = 'none'
            AND sector = 'urn:easy-auth:native-client:' || id::text)
    );
