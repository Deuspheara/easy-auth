CREATE TABLE auth_realms (id uuid PRIMARY KEY);
CREATE TABLE auth_users (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    id uuid NOT NULL,
    email text NOT NULL CHECK (email = lower(email)),
    email_verified_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, email)
);
CREATE TABLE auth_email_challenges (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    browser_hash bytea NOT NULL CHECK (octet_length(browser_hash) = 32),
    email text NOT NULL,
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '10 minutes'),
    PRIMARY KEY (realm_id, token_hash)
);
CREATE INDEX auth_challenge_expiry ON auth_email_challenges(expires_at);
CREATE TABLE auth_sessions (
    realm_id uuid NOT NULL,
    id uuid NOT NULL,
    user_id uuid NOT NULL,
    token_hash bytea NOT NULL CHECK (octet_length(token_hash) = 32),
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL DEFAULT (now() + interval '7 days'),
    revoked_at timestamptz,
    PRIMARY KEY (realm_id, id),
    UNIQUE (realm_id, token_hash),
    FOREIGN KEY (realm_id, user_id) REFERENCES auth_users(realm_id, id) ON DELETE CASCADE
);
CREATE INDEX auth_session_user ON auth_sessions(realm_id, user_id);
CREATE TABLE auth_rate_buckets (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    dimension text NOT NULL CHECK (dimension IN ('email', 'source')),
    key_hash bytea NOT NULL,
    window_id bigint NOT NULL,
    attempts integer NOT NULL CHECK (attempts > 0),
    PRIMARY KEY (realm_id, dimension, key_hash, window_id)
);
CREATE TABLE auth_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    user_id uuid NOT NULL,
    kind text NOT NULL CHECK (kind IN ('email_authenticated', 'session_revoked')),
    occurred_at timestamptz NOT NULL DEFAULT now()
);
