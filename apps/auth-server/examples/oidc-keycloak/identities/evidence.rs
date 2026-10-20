use auth_core::*;
use auth_postgres::Postgres;
use serde_json::{Value, json};
use sqlx::PgPool;
use uuid::Uuid;

pub(super) async fn rejects(
    store: &Postgres,
    configuration: &OAuthConnection,
    session: &Secret,
) -> Result<bool> {
    match store
        .authenticate(configuration.realm(), session.verifier())
        .await
    {
        Err(Error::Unauthorized) => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(error),
    }
}
pub(super) async fn session(
    store: &Postgres,
    pool: &PgPool,
    policy: &OidcIdentityPolicy,
    user: &User,
    secret: &Secret,
    authenticated_at: Option<u64>,
) -> Result<(bool, bool)> {
    let c = policy.configuration();
    let actual = store.authenticate(c.realm(), secret.verifier()).await?;
    let (method,identity,revision,time): (String,Option<Uuid>,Option<Uuid>,Option<i64>)=sqlx::query_as(r#"
        SELECT authentication_method,oidc_identity_id,oidc_revision,
            CASE WHEN isfinite(authenticated_at) THEN extract(epoch FROM authenticated_at)::bigint ELSE NULL END
        FROM auth_sessions WHERE realm_id=$1 AND token_hash=$2
    "#).bind(c.realm()).bind(secret.verifier().as_slice()).fetch_one(pool).await.map_err(|_|Error::Unavailable)?;
    let expected = authenticated_at
        .map(i64::try_from)
        .transpose()
        .map_err(|_| Error::Unavailable)?;
    Ok((
        actual == *user && method == "oidc" && identity.is_some() && revision == Some(c.revision()),
        time == expected,
    ))
}
pub(super) async fn facts(pool: &PgPool) -> Result<Value> {
    let row:(i64,i64,i64,i64,i64)=sqlx::query_as(r#"
        SELECT (SELECT count(*) FROM auth_oidc_identities),
          (SELECT count(*) FROM auth_users WHERE authentication_policy='provider_required'),
          (SELECT count(*) FROM auth_users WHERE authentication_policy='provider_required' AND email IS NOT NULL),
          (SELECT count(*) FROM auth_sessions WHERE authentication_method='oidc'),
          (SELECT count(*) FROM auth_sessions s JOIN auth_users u ON u.realm_id=s.realm_id AND u.id=s.user_id
            WHERE u.authentication_policy='provider_required' AND s.authentication_method<>'oidc')
    "#).fetch_one(pool).await.map_err(|_|Error::Unavailable)?;
    Ok(
        json!({"identities":row.0,"provider_users":row.1,"provider_contacts":row.2,"oidc_sessions":row.3,"weak_provider_sessions":row.4}),
    )
}
