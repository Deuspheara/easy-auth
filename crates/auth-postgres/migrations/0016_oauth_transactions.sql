-- Configuration is written only by trusted composition, never browser callbacks.
CREATE TABLE auth_oauth_connections (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    id uuid NOT NULL,
    client_id uuid NOT NULL,
    revision uuid NOT NULL,
    issuer text NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    provider_client text NOT NULL CHECK (octet_length(provider_client) BETWEEN 1 AND 256),
    redirect_uri text NOT NULL UNIQUE CHECK (octet_length(redirect_uri) BETWEEN 1 AND 2048),
    defense text NOT NULL CHECK (defense IN ('issuer','dedicated_redirect')),
    enabled boolean NOT NULL,
    PRIMARY KEY (realm_id,id,client_id)
);

CREATE TABLE auth_oauth_transactions (
    realm_id uuid NOT NULL,
    connection_id uuid NOT NULL,
    client_id uuid NOT NULL,
    revision uuid NOT NULL,
    state_hash bytea NOT NULL CHECK (octet_length(state_hash)=32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash)=32),
    nonce_hash bytea NOT NULL CHECK (octet_length(nonce_hash)=32),
    pkce_hash bytea NOT NULL CHECK (octet_length(pkce_hash)=32),
    purpose text NOT NULL CHECK (purpose IN ('sign_in','link')),
    user_id uuid,
    session_id uuid,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK (isfinite(created_at)),
    expires_at timestamptz NOT NULL CHECK (isfinite(expires_at)),
    PRIMARY KEY (realm_id,state_hash),
    FOREIGN KEY (realm_id,connection_id,client_id) REFERENCES auth_oauth_connections(realm_id,id,client_id) ON DELETE CASCADE,
    FOREIGN KEY (realm_id,session_id,user_id) REFERENCES auth_sessions(realm_id,id,user_id) ON DELETE CASCADE,
    CHECK ((purpose='sign_in' AND user_id IS NULL AND session_id IS NULL)
        OR (purpose='link' AND user_id IS NOT NULL AND session_id IS NOT NULL)),
    CHECK (expires_at>created_at AND expires_at<=created_at+interval '5 minutes')
);
CREATE INDEX auth_oauth_transactions_browser ON auth_oauth_transactions(realm_id,browser_hash);

CREATE TABLE auth_oauth_admission (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    dimension text NOT NULL CHECK (dimension IN ('start_browser','start_source','consume_browser','consume_source')),
    key_hash bytea NOT NULL CHECK (octet_length(key_hash)=32),
    window_id bigint NOT NULL,
    attempts integer NOT NULL CHECK (attempts>0),
    PRIMARY KEY (realm_id,dimension,key_hash,window_id)
);
