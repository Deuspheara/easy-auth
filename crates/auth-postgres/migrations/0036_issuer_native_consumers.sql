-- Separate operator-authorized introspection consumers; no public native client
-- gains authentication, and installing the schema enables no consumer.
CREATE TABLE auth_issuer_native_consumers (
    realm_id uuid NOT NULL,
    issuer text COLLATE "C" NOT NULL CHECK(issuer LIKE 'https://%'),
    consumer_id uuid NOT NULL,
    audience_id uuid NOT NULL CHECK(audience_id<>consumer_id),
    revision uuid NOT NULL CHECK(revision<>'00000000-0000-0000-0000-000000000000'),
    consumer_revision uuid NOT NULL CHECK(consumer_revision<>'00000000-0000-0000-0000-000000000000'),
    audience_revision uuid NOT NULL CHECK(audience_revision<>'00000000-0000-0000-0000-000000000000'),
    enabled boolean NOT NULL DEFAULT false,
    PRIMARY KEY(realm_id,issuer,consumer_id,audience_id),
    FOREIGN KEY(realm_id,consumer_id) REFERENCES auth_issuer_clients(realm_id,id) ON DELETE CASCADE,
    FOREIGN KEY(realm_id,audience_id) REFERENCES auth_issuer_clients(realm_id,id) ON DELETE CASCADE
);
