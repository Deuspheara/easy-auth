-- Stateful access revocation is distinct from local-session and offline ID-token
-- validity. This immutable timestamp cannot be cleared by a protocol operation.
ALTER TABLE auth_issuer_access_tokens ADD COLUMN revoked_at_us bigint
    CHECK (revoked_at_us IS NULL OR revoked_at_us>=issued_at_us);
