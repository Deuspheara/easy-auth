-- Protected captured grants only. No plaintext token/client secret, email,
-- subject or local-session credential is accepted by this ledger.
ALTER TABLE auth_oidc_identities ADD CONSTRAINT auth_oidc_identity_grant_source
    UNIQUE(realm_id,id,connection_id,client_id);
CREATE TABLE auth_apple_grants (
    realm_id uuid NOT NULL REFERENCES auth_realms(id) ON DELETE CASCADE,
    id uuid NOT NULL CHECK(id<>'00000000-0000-0000-0000-000000000000'),
    connection_id uuid NOT NULL CHECK(connection_id<>'00000000-0000-0000-0000-000000000000'),
    client_id uuid NOT NULL CHECK(client_id<>'00000000-0000-0000-0000-000000000000'),
    provider_client text NOT NULL CHECK(octet_length(provider_client) BETWEEN 1 AND 1024),
    identity_id uuid,
    binding_identity_id uuid NOT NULL CHECK(binding_identity_id<>'00000000-0000-0000-0000-000000000000'),
    key_id uuid CHECK(key_id IS NULL OR key_id<>'00000000-0000-0000-0000-000000000000'),
    ciphertext text CHECK(ciphertext IS NULL OR (octet_length(ciphertext) BETWEEN 1 AND 65536 AND ciphertext !~ '[^A-Za-z0-9_.-]')),
    version bigint NOT NULL DEFAULT 1 CHECK(version>0),
    state text NOT NULL DEFAULT 'active' CHECK(state IN ('active','pending','leased','failed','completed','expired')),
    attempts integer NOT NULL DEFAULT 0 CHECK(attempts BETWEEN 0 AND 8),
    created_at timestamptz NOT NULL DEFAULT clock_timestamp() CHECK(isfinite(created_at)),
    queued_at timestamptz,
    next_attempt_at timestamptz,
    expires_at timestamptz,
    lease_id uuid CHECK(lease_id IS NULL OR lease_id<>'00000000-0000-0000-0000-000000000000'),
    lease_until timestamptz,
    finished_at timestamptz,
    failure text CHECK(failure IN ('transport','provider','configuration','unavailable','expired')),
    CHECK(queued_at IS NULL OR isfinite(queued_at)),
    CHECK(next_attempt_at IS NULL OR isfinite(next_attempt_at)),
    CHECK(expires_at IS NULL OR (isfinite(expires_at) AND queued_at IS NOT NULL AND expires_at=queued_at+interval '604800 seconds')),
    CHECK(lease_until IS NULL OR (expires_at IS NOT NULL AND isfinite(lease_until) AND lease_until<=expires_at)),
    CHECK(state<>'failed' OR (attempts=8 AND failure IS NOT NULL)),
    PRIMARY KEY(realm_id,id),
    FOREIGN KEY(realm_id,identity_id,connection_id,client_id)
        REFERENCES auth_oidc_identities(realm_id,id,connection_id,client_id),
    CONSTRAINT auth_apple_grant_lifecycle CHECK (
        (state='active' AND identity_id IS NOT NULL AND identity_id=binding_identity_id
            AND key_id IS NOT NULL AND ciphertext IS NOT NULL AND attempts=0
            AND queued_at IS NULL AND next_attempt_at IS NULL AND expires_at IS NULL
            AND lease_id IS NULL AND lease_until IS NULL AND finished_at IS NULL AND failure IS NULL)
        OR (state IN ('pending','leased','failed') AND identity_id IS NULL AND key_id IS NOT NULL
            AND ciphertext IS NOT NULL AND queued_at IS NOT NULL AND isfinite(queued_at)
            AND next_attempt_at IS NOT NULL AND isfinite(next_attempt_at)
            AND expires_at IS NOT NULL AND expires_at=queued_at+interval '604800 seconds'
            AND finished_at IS NULL
            AND ((state='leased' AND lease_id IS NOT NULL AND lease_until IS NOT NULL AND isfinite(lease_until))
                OR (state<>'leased' AND lease_id IS NULL AND lease_until IS NULL)))
        OR (state IN ('completed','expired') AND identity_id IS NULL AND key_id IS NULL AND ciphertext IS NULL
            AND queued_at IS NOT NULL AND expires_at IS NOT NULL
            AND finished_at IS NOT NULL AND isfinite(finished_at)
            AND lease_id IS NULL AND lease_until IS NULL
            AND ((state='completed' AND failure IS NULL) OR (state='expired' AND failure='expired')))
    )
);
CREATE INDEX auth_apple_grants_due ON auth_apple_grants(realm_id,connection_id,client_id,next_attempt_at,id)
    WHERE state IN ('pending','leased');
CREATE INDEX auth_apple_grants_identity ON auth_apple_grants(realm_id,identity_id)
    WHERE identity_id IS NOT NULL;

-- The old/default feature-disabled deletion path must not cascade away captured
-- credentials. An immutable opaque identity UUID remains only as envelope binding;
-- no user FK, subject, email or account attributes are retained in the job.
CREATE FUNCTION auth_queue_apple_identity_grants() RETURNS trigger LANGUAGE plpgsql AS $$
DECLARE queued timestamptz:=clock_timestamp();
BEGIN
    UPDATE auth_apple_grants SET identity_id=NULL,state='pending',queued_at=queued,
        next_attempt_at=queued,expires_at=queued+interval '604800 seconds',version=version+1
        WHERE realm_id=OLD.realm_id AND identity_id=OLD.id AND state='active';
    RETURN OLD;
END $$;
CREATE TRIGGER auth_queue_apple_identity_grants BEFORE DELETE ON auth_oidc_identities
    FOR EACH ROW EXECUTE FUNCTION auth_queue_apple_identity_grants();
