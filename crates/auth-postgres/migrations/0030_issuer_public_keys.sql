-- Operator-provisioned issuer public metadata only. Private keys never enter SQL.
CREATE TABLE auth_issuer_key_sets (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    issuer text COLLATE "C" NOT NULL CHECK (octet_length(issuer) BETWEEN 1 AND 2048),
    revision uuid NOT NULL CHECK (revision <> '00000000-0000-0000-0000-000000000000'),
    active_key uuid,
    enabled boolean NOT NULL DEFAULT false,
    bootstrapped boolean NOT NULL DEFAULT false,
    PRIMARY KEY (realm_id,issuer),
    CHECK (NOT enabled OR active_key IS NOT NULL),
    CHECK (bootstrapped OR active_key IS NULL)
);
CREATE TABLE auth_issuer_keys (
    realm_id uuid NOT NULL,
    issuer text COLLATE "C" NOT NULL,
    id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    public_jwk jsonb NOT NULL CHECK (
        jsonb_typeof(public_jwk)='object'
        AND octet_length(public_jwk::text)<=2048
        AND public_jwk ?& ARRAY['kid','kty','n','e','alg','use','key_ops']
        AND public_jwk-ARRAY['kid','kty','n','e','alg','use','key_ops']='{}'::jsonb
        AND jsonb_typeof(public_jwk->'kid')='string'
        AND jsonb_typeof(public_jwk->'kty')='string'
        AND jsonb_typeof(public_jwk->'alg')='string'
        AND jsonb_typeof(public_jwk->'use')='string'
        AND public_jwk->>'kid'=id::text
        AND public_jwk->>'kty'='RSA' AND public_jwk->>'alg'='RS256'
        AND public_jwk->>'use'='sig' AND public_jwk->'key_ops'='["verify"]'::jsonb
        AND jsonb_typeof(public_jwk->'n')='string'
        AND jsonb_typeof(public_jwk->'e')='string'
    ),
    sign_from_us bigint NOT NULL CHECK (sign_from_us>=0),
    sign_until_us bigint NOT NULL CHECK (sign_until_us>sign_from_us),
    verify_until_us bigint NOT NULL CHECK (verify_until_us>sign_until_us
        AND verify_until_us-sign_until_us>=300000000),
    created_at_us bigint NOT NULL DEFAULT ((extract(epoch FROM clock_timestamp())*1000000)::bigint)
        CHECK (created_at_us>=0),
    -- Fresh publication/reenablement must propagate even for an old key ID.
    ready_at_us bigint NOT NULL DEFAULT ((extract(epoch FROM clock_timestamp())*1000000)::bigint+300000000)
        CHECK (ready_at_us>=0),
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (realm_id,issuer,id),
    FOREIGN KEY (realm_id,issuer) REFERENCES auth_issuer_key_sets(realm_id,issuer)
);
ALTER TABLE auth_issuer_key_sets ADD CONSTRAINT auth_issuer_active_key
    FOREIGN KEY (realm_id,issuer,active_key) REFERENCES auth_issuer_keys(realm_id,issuer,id);
CREATE INDEX auth_issuer_key_publication ON auth_issuer_keys(realm_id,issuer,verify_until_us);
