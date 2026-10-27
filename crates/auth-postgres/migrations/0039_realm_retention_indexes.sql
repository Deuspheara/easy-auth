-- Explicit realm maintenance scans expiry, not owner inventory. Preserve all
-- published data/constraints; these indexes also bound FK/reference lookups before
-- parent pruning. Apply with writers drained and fresh connections afterward.
CREATE INDEX auth_retention_audit_age ON auth_audit(realm_id,occurred_at);
CREATE INDEX auth_retention_audit_actor ON auth_audit(realm_id,actor_session_id) WHERE actor_session_id IS NOT NULL;
CREATE INDEX auth_retention_audit_session ON auth_audit(realm_id,session_id) WHERE session_id IS NOT NULL;
CREATE INDEX auth_retention_audit_authorization ON auth_audit(realm_id,issuer_authorization_id) WHERE issuer_authorization_id IS NOT NULL;
CREATE INDEX auth_retention_audit_generation ON auth_audit(realm_id,issuer_family_id,issuer_generation) WHERE issuer_family_id IS NOT NULL;

CREATE INDEX auth_retention_email_challenge ON auth_email_challenges(realm_id,expires_at);
CREATE INDEX auth_retention_password_reset ON auth_password_resets(realm_id,expires_at);
CREATE INDEX auth_retention_email_change ON auth_email_changes(realm_id,expires_at);
CREATE INDEX auth_retention_account_deletion ON auth_account_deletions(realm_id,expires_at);
CREATE INDEX auth_retention_email_attachment ON auth_email_attachments(realm_id,expires_at);
CREATE INDEX auth_retention_passkey_enrollment ON auth_passkey_enrollments(realm_id,expires_at);
CREATE INDEX auth_retention_passkey_authentication ON auth_passkey_authentications(realm_id,expires_at);
CREATE INDEX auth_retention_recovery_setup ON auth_passkey_recovery_setups(realm_id,expires_at);
CREATE INDEX auth_retention_recovery_replacement ON auth_passkey_recovery_replacements(realm_id,expires_at);
CREATE INDEX auth_retention_recovery_claim ON auth_passkey_recovery_claims(realm_id,expires_at);
CREATE INDEX auth_retention_oauth_transaction ON auth_oauth_transactions(realm_id,expires_at);
CREATE INDEX auth_retention_saml_replay ON auth_saml_replays(realm_id,retain_until);
CREATE INDEX auth_retention_session ON auth_sessions(realm_id,expires_at);
CREATE INDEX auth_retention_access ON auth_issuer_access_tokens(realm_id,expires_at_us);
CREATE INDEX auth_retention_family ON auth_issuer_native_families(realm_id,expires_at_us);
CREATE INDEX auth_retention_consent ON auth_issuer_native_consents(realm_id,grant_expires_at_us);
CREATE INDEX auth_retention_authorization ON auth_issuer_authorizations(realm_id,expires_at_us);
CREATE INDEX auth_retention_notice ON auth_security_notifications(realm_id,created_at);
CREATE INDEX auth_retention_rate ON auth_rate_buckets(realm_id,window_id);
CREATE INDEX auth_retention_oauth_admission ON auth_oauth_admission(realm_id,window_id);
CREATE INDEX auth_retention_issuer_admission ON auth_issuer_token_admission(realm_id,window_id);

CREATE INDEX auth_retention_authorization_session ON auth_issuer_authorizations(realm_id,session_id);
CREATE INDEX auth_retention_change_session ON auth_email_changes(realm_id,session_id);
CREATE INDEX auth_retention_deletion_session ON auth_account_deletions(realm_id,session_id);
CREATE INDEX auth_retention_attachment_session ON auth_email_attachments(realm_id,session_id);
CREATE INDEX auth_retention_oauth_session ON auth_oauth_transactions(realm_id,session_id) WHERE session_id IS NOT NULL;
CREATE INDEX auth_retention_enrollment_session ON auth_passkey_enrollments(realm_id,session_id);
CREATE INDEX auth_retention_setup_session ON auth_passkey_recovery_setups(realm_id,session_id);
CREATE INDEX auth_retention_saml_session ON auth_saml_requests(realm_id,session_id) WHERE session_id IS NOT NULL;

CREATE INDEX auth_retention_apple_expiry ON auth_apple_grants(realm_id,expires_at,id) WHERE state IN ('pending','leased','failed');
CREATE INDEX auth_retention_apple_lease ON auth_apple_grants(realm_id,lease_until,id) WHERE state='leased' AND attempts=8;
CREATE INDEX auth_retention_apple_terminal ON auth_apple_grants(realm_id,finished_at,id) WHERE state IN ('completed','expired');
