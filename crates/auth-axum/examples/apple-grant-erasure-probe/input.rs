use super::ProbeResult;
use auth_core::Secret;
use serde::Deserialize;
use sqlx::{PgPool, postgres::PgPoolOptions};
use std::io::Read;
use uuid::Uuid;

pub(super) struct Input {
    pub realm: Uuid,
    pub session: Secret,
}
pub(super) fn read() -> ProbeResult<Input> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Wire {
        realm: Uuid,
        session: String,
    }
    let wire: Wire = serde_json::from_reader(std::io::stdin().lock().take(4096))?;
    if wire.realm.is_nil() {
        return Err("owned realm required".into());
    }
    Ok(Input {
        realm: wire.realm,
        session: Secret::parse(wire.session)?,
    })
}
pub(super) async fn pool() -> ProbeResult<PgPool> {
    let value = std::env::var("DATABASE_URL")?;
    let url = url::Url::parse(&value)?;
    let suffix = url
        .path()
        .strip_prefix("/easy_auth_oidc_")
        .ok_or("owned database required")?;
    if !matches!(url.scheme(), "postgres" | "postgresql")
        || url.host_str() != Some("127.0.0.1")
        || suffix.len() != 32
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("owned loopback database required".into());
    }
    Ok(PgPoolOptions::new()
        .max_connections(1)
        .connect(&value)
        .await?)
}
