use async_trait::async_trait;
use easy_auth_adoption_probes::{PASSWORD, Probe, Result, SESSIONS, measure, pool};
use rustauth_core::{
    RustAuthOptions,
    auth::{
        email_password::{EmailPasswordAuth, EmailPasswordConfig, SignUpInput},
        session::{GetSessionInput, SessionAuth},
    },
    context::{AuthContext, create_auth_context_with_adapter},
    cookies::{SessionCookieOptions, set_session_cookie},
    db::DbAdapter,
};
use rustauth_sqlx::PostgresAdapter;
use std::sync::Arc;

struct RustAuthProbe {
    context: AuthContext,
    cookies: Vec<String>,
}
#[async_trait]
impl Probe for RustAuthProbe {
    async fn validate(&self, session: usize) -> Result<bool> {
        Ok(SessionAuth::new(&self.context)?
            .get_session(GetSessionInput::new(&self.cookies[session]))
            .await?
            .and_then(|result| result.user)
            .is_some())
    }
    async fn revoke(&self, session: usize) -> Result<()> {
        SessionAuth::new(&self.context)?
            .sign_out(&self.cookies[session])
            .await?;
        Ok(())
    }
}
#[tokio::main(worker_threads = 2)]
async fn main() -> Result<()> {
    let adapter = Arc::new(PostgresAdapter::new(pool().await?));
    let options = RustAuthOptions::new()
        .secret("local-comparison-fixture-at-least-thirty-two-bytes")
        .base_url("http://127.0.0.1:58419");
    let context = create_auth_context_with_adapter(options, adapter.clone())?;
    adapter.create_schema(&context.db_schema, None).await?;
    let mut cookies = Vec::new();
    for index in 0..SESSIONS {
        let result =
            EmailPasswordAuth::with_defaults(adapter.as_ref(), EmailPasswordConfig::default())
                .sign_up(SignUpInput::new(
                    "Comparison",
                    format!("user{index}@example.test"),
                    PASSWORD,
                ))
                .await?;
        let values = set_session_cookie(
            &context.auth_cookies,
            &context.secret,
            &result.session.token,
            SessionCookieOptions::default(),
        )?;
        cookies.push(
            values
                .iter()
                .map(|cookie| format!("{}={}", cookie.name, cookie.value))
                .collect::<Vec<_>>()
                .join("; "),
        );
    }
    measure(
        "rustauth-core-sqlx",
        Arc::new(RustAuthProbe { context, cookies }),
    )
    .await
}
