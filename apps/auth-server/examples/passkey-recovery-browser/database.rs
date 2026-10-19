use sqlx::postgres::PgPoolOptions;
use std::error::Error;
use url::Url;

pub(super) fn require_loopback(url: &Url) -> Result<(), Box<dyn Error>> {
    super::baseline::require_loopback(url)
}
pub(super) async fn facts(url: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut facts = super::baseline::facts(url).await?;
    let pool = PgPoolOptions::new().max_connections(1).connect(url).await?;
    let result = collect(&pool, &mut facts).await;
    pool.close().await;
    result?;
    Ok(facts)
}
async fn collect(pool: &sqlx::PgPool, facts: &mut serde_json::Value) -> Result<(), sqlx::Error> {
    for (name, query) in [
        (
            "recovery_started",
            "SELECT count(*) FROM auth_audit WHERE kind='passkey_recovery_started'",
        ),
        (
            "recovery_cancelled",
            "SELECT count(*) FROM auth_audit WHERE kind='passkey_recovery_cancelled'",
        ),
        (
            "recovery_completed",
            "SELECT count(*) FROM auth_audit WHERE kind='passkey_recovered'",
        ),
        (
            // Legacy total includes unverified registration rows, not just
            // credentials that have advanced to private assertion verification.
            "recovery_candidates",
            "SELECT count(*) FROM auth_passkey_recovery_replacements",
        ),
        (
            "recovery_registrations_pending",
            "SELECT count(*) FROM auth_passkey_recovery_replacements WHERE stage='registration'",
        ),
        (
            "recovery_assertions_pending",
            "SELECT count(*) FROM auth_passkey_recovery_replacements WHERE stage='assertion'",
        ),
        (
            "recovery_pending",
            "SELECT count(*) FROM auth_passkey_recovery_claims WHERE completed_at IS NULL AND cancelled_at IS NULL",
        ),
        (
            "recovery_codes_unused",
            "SELECT count(*) FROM auth_passkey_recovery_codes WHERE consumed_at IS NULL",
        ),
        (
            "recovery_notices_pending_all",
            "SELECT count(*) FROM auth_security_notifications WHERE kind LIKE 'passkey_recovery_%'",
        ),
        (
            "invalid_completion_provenance",
            "SELECT count(*) FROM auth_audit a JOIN auth_sessions s ON s.realm_id=a.realm_id AND s.id=a.session_id WHERE a.kind='passkey_recovered' AND (s.user_id<>a.user_id OR s.authentication_method<>'passkey' OR a.actor_session_id IS NOT NULL OR a.recovery_claim_id IS NULL)",
        ),
        (
            "recovery_source_attempts",
            "SELECT coalesce(sum(attempts),0)::bigint FROM auth_rate_buckets WHERE dimension='passkey_recovery_source'",
        ),
    ] {
        let count: i64 = sqlx::query_scalar(query).fetch_one(pool).await?;
        facts["database"][name] = count.into();
    }
    Ok(())
}
