-- Trusted administration applies policy and a fresh connection revision together.
-- A stale row is never authority: final identity resolution must compare both
-- revisions and the complete typed policy under the enabled configuration lock.
CREATE TABLE auth_oidc_identity_policies (
    realm_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    client_id uuid NOT NULL,
    revision uuid NOT NULL,
    allowed_issuers text[] NOT NULL CHECK (
        array_ndims(allowed_issuers)=1 AND array_lower(allowed_issuers,1)=1
        AND cardinality(allowed_issuers) BETWEEN 1 AND 8
        AND array_position(allowed_issuers,NULL) IS NULL
        AND octet_length(array_to_string(allowed_issuers,''))<=16384
    ),
    display_claim text NOT NULL CHECK (display_claim IN ('sub','name','preferred_username')),
    jit text NOT NULL DEFAULT 'deny' CHECK (jit IN ('deny','allow')),
    PRIMARY KEY (realm_id,connection_id,client_id),
    FOREIGN KEY (realm_id,connection_id,client_id)
        REFERENCES auth_oauth_connections(realm_id,id,client_id) ON DELETE CASCADE
);
