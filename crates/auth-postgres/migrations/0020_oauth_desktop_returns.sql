-- Stable source authority is separate from each exact owned native return.
-- Existing HTTPS and exact native registrations retain their original behavior.
ALTER TABLE auth_oauth_connections ADD COLUMN redirect_policy text NOT NULL DEFAULT 'exact'
    CHECK (redirect_policy IN ('exact','desktop_loopback'));

ALTER TABLE auth_oauth_transactions ADD COLUMN redirect_uri text;
UPDATE auth_oauth_transactions t SET redirect_uri=c.redirect_uri
FROM auth_oauth_connections c
WHERE c.realm_id=t.realm_id AND c.id=t.connection_id AND c.client_id=t.client_id;
ALTER TABLE auth_oauth_transactions ALTER COLUMN redirect_uri SET NOT NULL;
ALTER TABLE auth_oauth_transactions ADD CHECK (octet_length(redirect_uri) BETWEEN 1 AND 2048);
