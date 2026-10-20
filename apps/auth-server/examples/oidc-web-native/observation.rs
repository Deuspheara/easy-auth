use super::FixtureResult;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};
use uuid::Uuid;

pub(super) struct Source {
    pub realm: Uuid,
    pub connection: Uuid,
    pub client: Uuid,
    pub issuer: String,
    provider_client: String,
    redirect: String,
    revision: Option<Uuid>,
}
impl Source {
    pub fn new(config: &Value) -> FixtureResult<Self> {
        Ok(Self {
            realm: config["realm"].as_str().ok_or("realm")?.parse()?,
            connection: config["connection"].as_str().ok_or("connection")?.parse()?,
            client: config["local_client"]
                .as_str()
                .ok_or("local client")?
                .parse()?,
            issuer: config["issuer"].as_str().ok_or("issuer")?.to_owned(),
            provider_client: config["provider_client"]
                .as_str()
                .ok_or("provider client")?
                .to_owned(),
            redirect: config["redirect"].as_str().ok_or("callback")?.to_owned(),
            revision: None,
        })
    }
    pub async fn facts(&mut self, pool: &PgPool) -> FixtureResult<Value> {
        let row=sqlx::query("SELECT c.revision,c.enabled,p.jit,c.revision=p.revision AS aligned FROM auth_oauth_connections c JOIN auth_oidc_identity_policies p ON p.realm_id=c.realm_id AND p.connection_id=c.id AND p.client_id=c.client_id WHERE c.realm_id=$1 AND c.id=$2 AND c.client_id=$3 AND c.issuer=$4 AND c.provider_client=$5 AND c.redirect_uri=$6 AND c.defense='issuer' AND p.display_claim='sub' AND p.allowed_issuers=ARRAY[$4]::text[]")
            .bind(self.realm).bind(self.connection).bind(self.client).bind(&self.issuer).bind(&self.provider_client).bind(&self.redirect).fetch_one(pool).await?;
        let revision: Uuid = row.try_get("revision")?;
        let initial = *self.revision.get_or_insert(revision);
        let row_counts=sqlx::query("SELECT (SELECT count(*) FROM auth_users) AS users,(SELECT count(*) FROM auth_sessions) AS sessions,(SELECT count(*) FROM auth_sessions WHERE revoked_at IS NULL) AS live_sessions,(SELECT count(*) FROM auth_oidc_identities) AS identities,(SELECT count(*) FROM auth_audit) AS audit,(SELECT count(*) FROM auth_oauth_transactions) AS pending,(SELECT count(*) FROM auth_oidc_deleted_subjects) AS cooldown,(SELECT count(*) FROM auth_oidc_deleted_subjects WHERE blocked_until>clock_timestamp()) AS live_cooldown,(SELECT count(*) FROM auth_security_notifications) AS notices,(SELECT count(*) FROM auth_users WHERE email IS NOT NULL) AS contacts,(SELECT count(*) FROM auth_users WHERE authentication_policy='provider_required') AS provider_users,(SELECT count(*) FROM auth_sessions WHERE authentication_method='oidc') AS oidc_sessions,(SELECT count(*) FROM auth_audit WHERE user_id IS NOT NULL OR actor_session_id IS NOT NULL OR session_id IS NOT NULL OR NOT subject_erased) AS retained_subjects")
            .fetch_one(pool).await?;
        let mut counts = serde_json::Map::new();
        for key in [
            "users",
            "sessions",
            "live_sessions",
            "identities",
            "audit",
            "pending",
            "cooldown",
            "live_cooldown",
            "notices",
            "contacts",
            "provider_users",
            "oidc_sessions",
            "retained_subjects",
        ] {
            counts.insert(key.into(), json!(row_counts.try_get::<i64, _>(key)?));
        }
        Ok(
            json!({"result":"facts","source_current":row.try_get::<bool,_>("enabled")?&&row.try_get::<bool,_>("aligned")?&&initial==revision,
            "jit_allow":row.try_get::<String,_>("jit")?=="allow","facts":counts}),
        )
    }
}
