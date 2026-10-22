-- Bound request invalidation and parent cascades must be able to find one
-- owner's/session's state without scanning every connection in the realm.
-- Keep this unfiltered so foreign-key cascades can use the same access path.
CREATE INDEX auth_saml_requests_initiator
    ON auth_saml_requests (realm_id, user_id, session_id);
