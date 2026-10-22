-- Trusted outbound configuration only; no issuer endpoints or token authority.
CREATE TABLE auth_issuer_sectors (
    realm_id uuid NOT NULL REFERENCES auth_realms(id),
    host text COLLATE "C" NOT NULL CHECK (octet_length(host) BETWEEN 1 AND 253),
    PRIMARY KEY (realm_id, host)
);
CREATE TABLE auth_issuer_clients (
    realm_id uuid NOT NULL,
    id uuid NOT NULL CHECK (id <> '00000000-0000-0000-0000-000000000000'),
    revision uuid NOT NULL CHECK (revision <> '00000000-0000-0000-0000-000000000000'),
    sector text COLLATE "C" NOT NULL,
    redirect_uris text[] NOT NULL CHECK (
        array_ndims(redirect_uris) = 1 AND array_lower(redirect_uris,1) = 1
        AND cardinality(redirect_uris) BETWEEN 1 AND 8
        AND array_position(redirect_uris,NULL) IS NULL
    ),
    authentication text NOT NULL CHECK (authentication IN ('none','client_secret_basic')),
    secret_verifier bytea,
    consent text NOT NULL DEFAULT 'explicit' CHECK (consent = 'explicit'),
    subject_type text NOT NULL DEFAULT 'pairwise' CHECK (subject_type = 'pairwise'),
    enabled boolean NOT NULL DEFAULT true,
    PRIMARY KEY (realm_id,id),
    FOREIGN KEY (realm_id,sector) REFERENCES auth_issuer_sectors(realm_id,host),
    CHECK ((authentication = 'none' AND secret_verifier IS NULL)
        OR (authentication = 'client_secret_basic' AND secret_verifier IS NOT NULL
            AND octet_length(secret_verifier) = 32))
);
CREATE TABLE auth_issuer_subjects (
    realm_id uuid NOT NULL,
    sector text COLLATE "C" NOT NULL,
    user_id uuid NOT NULL,
    subject uuid NOT NULL CHECK (subject <> '00000000-0000-0000-0000-000000000000'),
    PRIMARY KEY (realm_id,sector,user_id),
    UNIQUE (realm_id,subject),
    FOREIGN KEY (realm_id,sector) REFERENCES auth_issuer_sectors(realm_id,host),
    FOREIGN KEY (realm_id,user_id) REFERENCES auth_users(realm_id,id) ON DELETE CASCADE
);
CREATE INDEX auth_issuer_subject_owner ON auth_issuer_subjects(realm_id,user_id);
