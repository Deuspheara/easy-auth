-- Gated fixed persistent-NameID mapping policy. No identities/session grant.
CREATE TABLE auth_saml_identity_policies (
    realm_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    client_id uuid NOT NULL,
    revision uuid NOT NULL,
    jit text NOT NULL DEFAULT 'deny' CHECK (jit IN ('deny','allow')),
    PRIMARY KEY (realm_id,connection_id,client_id),
    FOREIGN KEY (realm_id,connection_id,client_id)
        REFERENCES auth_saml_registrations(realm_id,id,client_id) ON DELETE CASCADE
);

-- Any registration/pin replacement or disable invalidates the previous policy
-- in the same transaction. A policy writer restores only its explicit new value.
CREATE FUNCTION auth_saml_invalidate_identity_policy() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.revision IS DISTINCT FROM OLD.revision THEN
        DELETE FROM auth_saml_identity_policies
        WHERE realm_id=NEW.realm_id AND connection_id=NEW.id AND client_id=NEW.client_id;
    END IF;
    RETURN NEW;
END $$;
CREATE TRIGGER auth_saml_invalidate_identity_policy
AFTER UPDATE OF revision ON auth_saml_registrations
FOR EACH ROW EXECUTE FUNCTION auth_saml_invalidate_identity_policy();
