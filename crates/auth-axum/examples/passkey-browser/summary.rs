use sqlx::PgPool;
use std::error::Error;

pub(super) async fn print(pool: &PgPool) -> Result<(), Box<dyn Error>> {
    let credentials: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys")
        .fetch_one(pool)
        .await?;
    let audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='passkey_enrolled'")
            .fetch_one(pool)
            .await?;
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey_enrollments")
        .fetch_one(pool)
        .await?;
    let postgres_version: String = sqlx::query_scalar("SELECT current_setting('server_version')")
        .fetch_one(pool)
        .await?;
    let authentication_audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='passkey_authenticated'")
            .fetch_one(pool)
            .await?;
    let passkey_sessions: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM auth_sessions WHERE authentication_method='passkey'",
    )
    .fetch_one(pool)
    .await?;
    let authentication_pending: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_passkey_authentications")
            .fetch_one(pool)
            .await?;
    let authentication_finish_attempts:i64=sqlx::query_scalar("SELECT coalesce(sum(attempts),0)::bigint FROM auth_rate_buckets WHERE dimension='passkey_auth_finish_source'").fetch_one(pool).await?;
    let backed_up_credentials: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE last_used_at IS NOT NULL AND convert_from(credential,'UTF8')::jsonb #>> '{cred,backup_state}'='true'").fetch_one(pool).await?;
    let zero_counter_credentials: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkeys WHERE last_used_at IS NOT NULL AND convert_from(credential,'UTF8')::jsonb #>> '{cred,counter}'='0'").fetch_one(pool).await?;
    let signup_audits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM auth_audit WHERE kind='passkey_signed_up'")
            .fetch_one(pool)
            .await?;
    let signup_users: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_users WHERE email IS NULL AND email_verified_at IS NULL AND authentication_policy='passkey_required'")
        .fetch_one(pool).await?;
    let signup_pending: i64 = sqlx::query_scalar("SELECT count(*) FROM auth_passkey_signups")
        .fetch_one(pool)
        .await?;
    let signup_finish_attempts: i64 = sqlx::query_scalar("SELECT coalesce(sum(attempts),0)::bigint FROM auth_rate_buckets WHERE dimension='passkey_signup_finish_source'")
        .fetch_one(pool).await?;
    println!(
        "{}",
        serde_json::json!({"credentials":credentials,"audits":audits,"pending":pending,"postgres_version":postgres_version,
            "authentication_audits":authentication_audits,"passkey_sessions":passkey_sessions,
            "authentication_pending":authentication_pending,"backed_up_credentials":backed_up_credentials,
            "authentication_finish_attempts":authentication_finish_attempts,
            "zero_counter_credentials":zero_counter_credentials,
            "signup_audits":signup_audits,"signup_users":signup_users,"signup_pending":signup_pending,
            "signup_finish_attempts":signup_finish_attempts})
    );
    Ok(())
}
