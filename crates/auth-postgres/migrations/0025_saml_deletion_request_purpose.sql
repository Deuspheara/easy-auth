-- Add a distinct SAML request purpose without rewriting original sign-in rows.
ALTER TABLE auth_saml_requests
    ADD COLUMN purpose text NOT NULL DEFAULT 'sign_in',
    ADD COLUMN user_id uuid,
    ADD COLUMN session_id uuid,
    ADD COLUMN identity_id uuid;
ALTER TABLE auth_saml_requests ADD CONSTRAINT auth_saml_request_purpose CHECK (
    (purpose='sign_in' AND user_id IS NULL AND session_id IS NULL AND identity_id IS NULL)
    OR (purpose='delete_account' AND user_id IS NOT NULL AND session_id IS NOT NULL AND identity_id IS NOT NULL)
);
ALTER TABLE auth_saml_identities ADD CONSTRAINT auth_saml_identity_request_source
    UNIQUE(realm_id,id,user_id,connection_id,client_id);
ALTER TABLE auth_sessions ADD CONSTRAINT auth_saml_session_request_source
    UNIQUE(realm_id,id,user_id,saml_identity_id,saml_revision);
ALTER TABLE auth_saml_requests ADD CONSTRAINT auth_saml_request_identity
    FOREIGN KEY(realm_id,identity_id,user_id,connection_id,client_id)
    REFERENCES auth_saml_identities(realm_id,id,user_id,connection_id,client_id) ON DELETE CASCADE;
ALTER TABLE auth_saml_requests ADD CONSTRAINT auth_saml_request_session
    FOREIGN KEY(realm_id,session_id,user_id,identity_id,revision)
    REFERENCES auth_sessions(realm_id,id,user_id,saml_identity_id,saml_revision) ON DELETE CASCADE;
