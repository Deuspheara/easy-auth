-- Trusted operator leaf pins only. No callback-selected metadata, PKI fallback,
-- signature result, identity grant or provider activation is stored here.
CREATE TABLE auth_saml_certificates (
    realm_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    client_id uuid NOT NULL,
    revision uuid NOT NULL,
    slot smallint NOT NULL CHECK (slot BETWEEN 0 AND 1),
    certificate_der bytea NOT NULL CHECK (octet_length(certificate_der) BETWEEN 1 AND 16384),
    fingerprint bytea NOT NULL CHECK (octet_length(fingerprint) = 32),
    approved_from bigint NOT NULL CHECK (approved_from >= 0),
    approved_until bigint NOT NULL CHECK (approved_until > approved_from),
    PRIMARY KEY (realm_id, connection_id, client_id, slot),
    UNIQUE (realm_id, connection_id, client_id, fingerprint),
    FOREIGN KEY (realm_id, connection_id, client_id)
        REFERENCES auth_saml_registrations(realm_id, id, client_id) ON DELETE CASCADE
);

-- Every registration replacement/disable already changes revision. Invalidate
-- old trust in that same transaction, including requests-only administration.
CREATE FUNCTION auth_saml_clear_revised_certificates() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    DELETE FROM auth_saml_certificates
      WHERE realm_id=OLD.realm_id AND connection_id=OLD.id AND client_id=OLD.client_id;
    RETURN NEW;
END;
$$;
CREATE TRIGGER auth_saml_clear_revised_certificates
    AFTER UPDATE OF revision ON auth_saml_registrations
    FOR EACH ROW WHEN (OLD.revision IS DISTINCT FROM NEW.revision)
    EXECUTE FUNCTION auth_saml_clear_revised_certificates();
