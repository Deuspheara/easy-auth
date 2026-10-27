// Each parent remains until all children have been independently pruned. These
// guards also preserve retained audit provenance; no cascade or deidentification
// is a substitute for explicit retention. All subqueries retain exact realm scope.
pub(super) const RECOVERY_CLAIM: &str = "t.expires_at<=statement_timestamp()
AND NOT EXISTS (SELECT 1 FROM auth_security_notifications n WHERE n.realm_id=t.realm_id AND n.recovery_claim_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_passkey_recovery_replacements r WHERE r.realm_id=t.realm_id AND r.claim_id=t.id)";

pub(super) const REFRESH_TOKEN: &str = "EXISTS (SELECT 1 FROM auth_issuer_native_families f WHERE f.realm_id=t.realm_id AND f.id=t.family_id AND f.expires_at_us<=floor(extract(epoch FROM statement_timestamp())*1000000)::bigint)
AND NOT EXISTS (SELECT 1 FROM auth_audit a WHERE a.realm_id=t.realm_id AND a.issuer_family_id=t.family_id AND a.issuer_generation=t.generation)";

pub(super) const FAMILY: &str = "t.expires_at_us<=floor(extract(epoch FROM statement_timestamp())*1000000)::bigint
AND NOT EXISTS (SELECT 1 FROM auth_issuer_access_tokens a WHERE a.realm_id=t.realm_id AND a.native_family_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_issuer_native_refresh_tokens r WHERE r.realm_id=t.realm_id AND r.family_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_audit a WHERE a.realm_id=t.realm_id AND a.issuer_family_id=t.id)";

pub(super) const CONSENT: &str = "t.grant_expires_at_us<=floor(extract(epoch FROM statement_timestamp())*1000000)::bigint
AND NOT EXISTS (SELECT 1 FROM auth_issuer_native_families f WHERE f.realm_id=t.realm_id AND f.authorization_id=t.authorization_id)";

pub(super) const AUTHORIZATION: &str = "t.expires_at_us<=floor(extract(epoch FROM statement_timestamp())*1000000)::bigint
AND NOT EXISTS (SELECT 1 FROM auth_issuer_access_tokens a WHERE a.realm_id=t.realm_id AND a.authorization_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_issuer_native_consents c WHERE c.realm_id=t.realm_id AND c.authorization_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_issuer_native_families f WHERE f.realm_id=t.realm_id AND f.authorization_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_audit a WHERE a.realm_id=t.realm_id AND a.issuer_authorization_id=t.id)";

pub(super) const SESSION: &str = "t.expires_at<=statement_timestamp()
AND NOT EXISTS (SELECT 1 FROM auth_audit a WHERE a.realm_id=t.realm_id AND (a.actor_session_id=t.id OR a.session_id=t.id))
AND NOT EXISTS (SELECT 1 FROM auth_issuer_authorizations a WHERE a.realm_id=t.realm_id AND a.session_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_account_deletions d WHERE d.realm_id=t.realm_id AND d.session_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_email_attachments a WHERE a.realm_id=t.realm_id AND a.session_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_email_changes c WHERE c.realm_id=t.realm_id AND c.session_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_oauth_transactions o WHERE o.realm_id=t.realm_id AND o.session_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_passkey_enrollments p WHERE p.realm_id=t.realm_id AND p.session_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_passkey_recovery_setups r WHERE r.realm_id=t.realm_id AND r.session_id=t.id)
AND NOT EXISTS (SELECT 1 FROM auth_saml_requests s WHERE s.realm_id=t.realm_id AND s.session_id=t.id)";
