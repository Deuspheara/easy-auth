use async_trait::async_trait;
use easy_auth_adoption_probes::{PASSWORD, Probe, Result, SESSIONS, measure, pool};
use lucid_auth::{AuthConfig, AuthService, EmailSignUpInput, postgres::PostgresStore};
use std::sync::Arc;

struct Lucid {
    service: AuthService,
    tokens: Vec<String>,
}
#[async_trait]
impl Probe for Lucid {
    async fn validate(&self, session: usize) -> Result<bool> {
        Ok(self.service.session(&self.tokens[session]).await?.is_some())
    }
    async fn revoke(&self, session: usize) -> Result<()> {
        Ok(self.service.sign_out(&self.tokens[session]).await?)
    }
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let store = Arc::new(PostgresStore::new(pool().await?, Default::default()));
    let mut config =
        AuthConfig::new(b"local-comparison-fixture-at-least-thirty-two-bytes".to_vec())?;
    config.set_base_url("http://127.0.0.1:58419")?;
    config.email_and_password.enabled = true;
    let service = AuthService::try_new(store.clone(), config)?;
    let schema = store.migrate_all(&service.plugin_migrations()).await?;
    if !schema.compatible {
        return Err("upstream schema incompatible".into());
    }
    let mut tokens = Vec::new();
    for index in 0..SESSIONS {
        let result = service
            .sign_up_email(
                EmailSignUpInput {
                    name: "Comparison".into(),
                    email: format!("user{index}@example.test"),
                    password: PASSWORD.into(),
                    image: None,
                    callback_url: None,
                    remember_me: Some(true),
                    username: None,
                    display_username: None,
                    additional_fields: Default::default(),
                },
                None,
                None,
            )
            .await?;
        tokens.push(result.token.ok_or("signup did not issue a session")?);
    }
    measure("lucid-auth-postgres", Arc::new(Lucid { service, tokens })).await
}
