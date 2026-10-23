-- Keep the original online row contract. Explicit native consent is marked and
-- has an immutable proposed grant; existing rows remain online and unchanged.
ALTER TABLE auth_issuer_authorizations
    ADD COLUMN native_refresh boolean NOT NULL DEFAULT false,
    ADD CONSTRAINT auth_issuer_native_consent_tuple UNIQUE
        (realm_id,id,issuer,client_id,client_revision,user_id,session_id,native_refresh);

CREATE TABLE auth_issuer_native_consents (
    realm_id uuid NOT NULL,
    authorization_id uuid NOT NULL,
    issuer text NOT NULL,
    client_id uuid NOT NULL,
    client_revision uuid NOT NULL,
    user_id uuid NOT NULL,
    session_id uuid NOT NULL,
    native_refresh boolean NOT NULL DEFAULT true CHECK (native_refresh),
    policy_revision uuid NOT NULL CHECK (policy_revision <> '00000000-0000-0000-0000-000000000000'),
    lifetime_seconds integer NOT NULL CHECK (lifetime_seconds BETWEEN 1 AND 604800),
    idle_seconds integer NOT NULL CHECK (idle_seconds BETWEEN 1 AND 86400 AND idle_seconds <= lifetime_seconds),
    prepared_at_us bigint NOT NULL CHECK (prepared_at_us >= 0),
    source_absolute_cap_us bigint NOT NULL CHECK (source_absolute_cap_us > prepared_at_us),
    grant_expires_at_us bigint NOT NULL CHECK (grant_expires_at_us > prepared_at_us
        AND grant_expires_at_us <= source_absolute_cap_us
        AND grant_expires_at_us <= prepared_at_us + lifetime_seconds::bigint * 1000000),
    approved_at_us bigint CHECK (approved_at_us >= prepared_at_us AND approved_at_us < grant_expires_at_us),
    PRIMARY KEY (realm_id,authorization_id),
    FOREIGN KEY (realm_id,authorization_id,issuer,client_id,client_revision,user_id,session_id,native_refresh)
        REFERENCES auth_issuer_authorizations(realm_id,id,issuer,client_id,client_revision,user_id,session_id,native_refresh)
        ON DELETE CASCADE
);
