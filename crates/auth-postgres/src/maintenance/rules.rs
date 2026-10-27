use super::references;
use auth_core::{RetentionCategory as Category, RetentionPolicy};
use sqlx::{Postgres, QueryBuilder};

pub(super) struct Rule {
    pub(super) table: &'static str,
    pub(super) order: &'static str,
    predicate: Predicate,
}

enum Predicate {
    Sql(&'static str),
    Audit(u32),
    Notices(Option<u32>),
}

impl Rule {
    fn sql(table: &'static str, order: &'static str, predicate: &'static str) -> Self {
        Self {
            table,
            order,
            predicate: Predicate::Sql(predicate),
        }
    }

    fn expiring(table: &'static str) -> Self {
        Self::sql(table, "t.expires_at", "t.expires_at<=statement_timestamp()")
    }

    pub(super) fn eligibility(&self, query: &mut QueryBuilder<'_, Postgres>) {
        match self.predicate {
            Predicate::Sql(predicate) => {
                query.push(predicate);
            }
            Predicate::Audit(seconds) => {
                query
                    .push("t.occurred_at<=statement_timestamp()-")
                    .push_bind(i64::from(seconds))
                    .push("*interval '1 second'");
            }
            Predicate::Notices(seconds) => {
                query.push("(t.lease_until IS NULL OR t.lease_until<=statement_timestamp()) AND ((t.attempts=8 AND ")
                    .push_bind(seconds.map(i64::from)).push("::bigint IS NOT NULL AND t.created_at<=statement_timestamp()-")
                    .push_bind(seconds.map(i64::from)).push("::bigint*interval '1 second') OR EXISTS (SELECT 1 FROM auth_passkey_recovery_claims c WHERE c.realm_id=t.realm_id AND c.id=t.recovery_claim_id AND c.expires_at<=statement_timestamp()))");
            }
        }
    }
}

// Only this closed match supplies SQL identifiers/expressions. Operator ages are
// validated core values and still bound as parameters. No caller-provided SQL.
pub(super) fn for_category(category: Category, policy: RetentionPolicy) -> Option<Rule> {
    Some(match category {
        Category::Audit => Rule {
            table: "auth_audit",
            order: "t.occurred_at",
            predicate: Predicate::Audit(policy.audit().seconds()?),
        },
        Category::Notifications => Rule {
            table: "auth_security_notifications",
            order: "t.created_at",
            predicate: Predicate::Notices(policy.exhausted_notices().seconds()),
        },
        Category::EmailChallenges => Rule::expiring("auth_email_challenges"),
        Category::PasswordResets => Rule::expiring("auth_password_resets"),
        Category::EmailChanges => Rule::expiring("auth_email_changes"),
        Category::AccountDeletions => Rule::expiring("auth_account_deletions"),
        Category::EmailAttachments => Rule::expiring("auth_email_attachments"),
        Category::PasskeyEnrollments => Rule::expiring("auth_passkey_enrollments"),
        Category::PasskeyAuthentications => Rule::expiring("auth_passkey_authentications"),
        Category::PasskeySignups => Rule::expiring("auth_passkey_signups"),
        Category::RecoverySetups => Rule::expiring("auth_passkey_recovery_setups"),
        Category::RecoveryReplacements => Rule::expiring("auth_passkey_recovery_replacements"),
        Category::RecoveryClaims => Rule::sql(
            "auth_passkey_recovery_claims",
            "t.expires_at",
            references::RECOVERY_CLAIM,
        ),
        Category::OAuthTransactions => Rule::expiring("auth_oauth_transactions"),
        Category::SamlRequests => Rule::expiring("auth_saml_requests"),
        Category::SamlReplays => Rule::sql(
            "auth_saml_replays",
            "t.retain_until",
            "t.retain_until<=statement_timestamp()",
        ),
        Category::OidcCooldowns => Rule::sql(
            "auth_oidc_deleted_subjects",
            "t.blocked_until",
            "t.blocked_until<=statement_timestamp()",
        ),
        Category::SamlCooldowns => Rule::sql(
            "auth_saml_deleted_subjects",
            "t.blocked_until",
            "t.blocked_until<=statement_timestamp()",
        ),
        // Existing stored window encoding is 600s for local/OAuth admission and
        // 60s for issuer admission. Keep the previous window as well as current/future.
        Category::RateBuckets => Rule::sql(
            "auth_rate_buckets",
            "t.window_id",
            "t.window_id<floor(extract(epoch FROM statement_timestamp())/600)::bigint-1",
        ),
        Category::OAuthAdmission => Rule::sql(
            "auth_oauth_admission",
            "t.window_id",
            "t.window_id<floor(extract(epoch FROM statement_timestamp())/600)::bigint-1",
        ),
        Category::IssuerAdmission => Rule::sql(
            "auth_issuer_token_admission",
            "t.window_id",
            "t.window_id<floor(extract(epoch FROM statement_timestamp())/60)::bigint-1",
        ),
        Category::IssuerAccessTokens => Rule::sql(
            "auth_issuer_access_tokens",
            "t.expires_at_us",
            "t.expires_at_us<=floor(extract(epoch FROM statement_timestamp())*1000000)::bigint",
        ),
        Category::IssuerRefreshTokens => Rule::sql(
            "auth_issuer_native_refresh_tokens",
            "t.family_id,t.generation",
            references::REFRESH_TOKEN,
        ),
        Category::IssuerFamilies => Rule::sql(
            "auth_issuer_native_families",
            "t.expires_at_us",
            references::FAMILY,
        ),
        Category::IssuerConsents => Rule::sql(
            "auth_issuer_native_consents",
            "t.grant_expires_at_us",
            references::CONSENT,
        ),
        Category::IssuerAuthorizations => Rule::sql(
            "auth_issuer_authorizations",
            "t.expires_at_us",
            references::AUTHORIZATION,
        ),
        Category::Sessions => Rule::sql("auth_sessions", "t.expires_at", references::SESSION),
        Category::AppleGrants => return None,
    })
}
