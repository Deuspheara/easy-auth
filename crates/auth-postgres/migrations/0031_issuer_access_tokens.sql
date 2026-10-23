-- The opaque access credential is distinct from local sessions and private keys.
ALTER TABLE auth_issuer_authorizations ADD CONSTRAINT auth_issuer_signed_owner
    UNIQUE(realm_id,id,issuer,client_id,user_id,session_id,subject);
CREATE TABLE auth_issuer_access_tokens (
    realm_id uuid NOT NULL,
    issuer text COLLATE "C" NOT NULL,
    id uuid NOT NULL CHECK(id<>'00000000-0000-0000-0000-000000000000'),
    authorization_id uuid NOT NULL,
    client_id uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    subject uuid NOT NULL,
    key_id uuid NOT NULL,
    access_hash bytea NOT NULL CHECK(octet_length(access_hash)=32),
    issued_at_us bigint NOT NULL CHECK(issued_at_us>=0),
    expires_at_us bigint NOT NULL CHECK(expires_at_us>issued_at_us
        AND expires_at_us-issued_at_us<=300000000),
    PRIMARY KEY(realm_id,id),
    UNIQUE(realm_id,access_hash),
    UNIQUE(realm_id,authorization_id),
    FOREIGN KEY(realm_id,issuer,key_id) REFERENCES auth_issuer_keys(realm_id,issuer,id),
    FOREIGN KEY(realm_id,authorization_id,issuer,client_id,user_id,session_id,subject)
        REFERENCES auth_issuer_authorizations(realm_id,id,issuer,client_id,user_id,session_id,subject)
        ON DELETE CASCADE
);
CREATE INDEX auth_issuer_access_owner ON auth_issuer_access_tokens(realm_id,user_id);
