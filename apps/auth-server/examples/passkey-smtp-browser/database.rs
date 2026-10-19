use sqlx::postgres::PgPoolOptions;
use std::error::Error;
use url::Url;

pub(super) fn require_loopback(url: &Url) -> Result<(), Box<dyn Error>> {
    if !matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")) {
        return Err("loopback PostgreSQL required".into());
    }
    Ok(())
}

pub(super) async fn facts(url: &str) -> Result<serde_json::Value, Box<dyn Error>> {
    let pool = PgPoolOptions::new().max_connections(1).connect(url).await?;
    let result = collect(&pool).await;
    pool.close().await;
    result
}

async fn collect(pool: &sqlx::PgPool) -> Result<serde_json::Value, Box<dyn Error>> {
    let mut facts = serde_json::Map::new();
    for (name, query) in [
        ("users", "SELECT count(*) FROM auth_users"),
        (
            "recovery_configured",
            "SELECT count(*) FROM auth_audit WHERE kind='passkey_recovery_configured'",
        ),
        (
            "recovery_codes",
            "SELECT count(*) FROM auth_passkey_recovery_codes",
        ),
        (
            "recovery_setups_pending",
            "SELECT count(*) FROM auth_passkey_recovery_setups",
        ),
        (
            "recovery_notices_pending",
            "SELECT count(*) FROM auth_security_notifications WHERE kind='passkey_recovery_changed'",
        ),
        (
            "invalid_recovery_provenance",
            "SELECT count(*) FROM auth_audit a JOIN auth_sessions s ON s.realm_id=a.realm_id AND s.id=a.actor_session_id WHERE a.kind='passkey_recovery_configured' AND (s.user_id<>a.user_id OR s.authentication_method<>'passkey' OR a.session_id IS NOT NULL OR a.passkey_id IS NOT NULL)",
        ),
        (
            "strong_verified_users",
            "SELECT count(*) FROM auth_users WHERE email IS NOT NULL AND email_verified_at IS NOT NULL AND authentication_policy='passkey_required'",
        ),
        ("credentials", "SELECT count(*) FROM auth_passkeys"),
        (
            "signup_audits",
            "SELECT count(*) FROM auth_audit WHERE kind='passkey_signed_up'",
        ),
        (
            "attachment_audits",
            "SELECT count(*) FROM auth_audit WHERE kind='email_attached'",
        ),
        (
            "authentication_audits",
            "SELECT count(*) FROM auth_audit WHERE kind='passkey_authenticated'",
        ),
        (
            "management_renames",
            "SELECT count(*) FROM auth_audit WHERE kind='passkey_renamed' AND passkey_id IS NOT NULL",
        ),
        (
            "management_removals",
            "SELECT count(*) FROM auth_audit WHERE kind='passkey_removed' AND passkey_id IS NOT NULL",
        ),
        (
            "management_notices_pending",
            "SELECT count(*) FROM auth_security_notifications WHERE kind='passkeys_changed'",
        ),
        (
            "unproven_remaining_keys",
            "SELECT count(*) FROM auth_passkeys WHERE last_used_at IS NULL",
        ),
        (
            "weak_sessions",
            "SELECT count(*) FROM auth_sessions WHERE authentication_method<>'passkey'",
        ),
        (
            "invalid_attachment_provenance",
            "SELECT count(*) FROM auth_audit a JOIN auth_sessions s ON s.realm_id=a.realm_id AND s.id=a.session_id JOIN auth_sessions actor ON actor.realm_id=a.realm_id AND actor.id=a.actor_session_id WHERE a.kind='email_attached' AND (s.user_id<>actor.user_id OR s.authentication_method<>actor.authentication_method OR s.authenticated_at<>actor.authenticated_at OR actor.revoked_at IS NULL)",
        ),
        (
            "attachment_pending",
            "SELECT count(*) FROM auth_email_attachments",
        ),
        (
            "signup_pending",
            "SELECT count(*) FROM auth_passkey_signups",
        ),
    ] {
        let count: i64 = sqlx::query_scalar(query).fetch_one(pool).await?;
        facts.insert(name.into(), count.into());
    }
    let version: String = sqlx::query_scalar("SHOW server_version")
        .fetch_one(pool)
        .await?;
    facts.insert("postgres_version".into(), version.into());
    Ok(serde_json::json!({"database":facts}))
}
