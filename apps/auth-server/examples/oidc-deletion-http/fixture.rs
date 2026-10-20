mod bootstrap;
mod setup;

use super::{
    FixtureResult,
    database::Database,
    mail::NoDelivery,
    observation::{self, Observation},
    read_command, send,
    server::Server,
    transactions::{Pending, Replay},
    transport::Http,
};
use auth_core::*;
use auth_postgres::Postgres;
use serde_json::{Value, json};
use std::{
    io::BufRead,
    sync::{Arc, atomic::Ordering},
};

struct Fixture {
    pool: sqlx::PgPool,
    store: Arc<Postgres>,
    policy: OidcIdentityPolicy,
    transactions: Arc<OAuthTransactions>,
    exchange: Arc<OidcCodeExchange>,
    auth: Auth,
    server: Server,
    observation: Arc<Observation>,
    mail: Arc<NoDelivery>,
    http: Arc<Http>,
    pending: Option<Pending>,
    replay: Option<Replay>,
    current: Option<Secret>,
}
impl Fixture {
    async fn command(&mut self, command: &Value) -> auth_core::Result<Value> {
        match command["command"].as_str() {
            Some("begin") => self.begin().await,
            Some("finish") => {
                self.finish(command["callback"].as_str().ok_or(Error::InvalidInput)?)
                    .await
            }
            Some("replay_state") => {
                self.replay
                    .as_ref()
                    .ok_or(Error::InvalidInput)?
                    .check(&self.transactions, self.policy.configuration())
                    .await
            }
            Some("status") => self.status().await,
            _ => Err(Error::InvalidInput),
        }
    }
    async fn status(&self) -> auth_core::Result<Value> {
        let current = match &self.current {
            Some(session) => match self.auth.authenticate(session).await {
                Ok(_) => true,
                Err(Error::Unauthorized) => false,
                Err(error) => return Err(error),
            },
            None => false,
        };
        self.store
            .check_oidc_connection(self.policy.configuration())
            .await?;
        let last = self.observation.last.lock().unwrap().clone();
        Ok(json!({"result":"status","current_session_valid":current,
            "configured_source_current":true,"deletion_calls":self.observation.calls.load(Ordering::SeqCst),
            "last_deletion":last,"mail_calls":self.mail.0.load(Ordering::SeqCst),
            "http_facts":observation::facts(&self.pool).await?}))
    }
}
fn classified(result: auth_core::Result<Value>) -> Value {
    match result {
        Ok(value) => value,
        Err(error) => {
            json!({"result":match error {Error::Unauthorized=>"unauthorized",Error::Unavailable=>"unavailable",Error::RateLimited=>"rate_limited",Error::InvalidInput=>"invalid_input"}})
        }
    }
}
pub(super) async fn run(
    config: Value,
    database: &Database,
    input: &mut impl BufRead,
) -> FixtureResult<()> {
    let mut fixture = Fixture::new(config, database).await?;
    let result = commands(&mut fixture, input).await;
    fixture.server.close().await;
    result
}
async fn commands(fixture: &mut Fixture, input: &mut impl BufRead) -> FixtureResult<()> {
    send(
        json!({"ready":true,"http_deletion_capability":true,"application_address":fixture.server.address.to_string()}),
    )?;
    while let Some(command) = read_command(input)? {
        if command["command"].as_str() == Some("close") {
            break;
        }
        let before = fixture.http.posts.load(Ordering::SeqCst);
        let mut value = classified(fixture.command(&command).await);
        value["id"] = command["id"].clone();
        value["post_delta"] = (fixture.http.posts.load(Ordering::SeqCst) - before).into();
        send(value)?;
    }
    let counts = observation::facts(&fixture.pool).await?;
    send(
        json!({"facts":{"users":counts["users"],"sessions":counts["sessions"],"audit":counts["audit"],"pending":counts["pending"]},"http_facts":counts}),
    )?;
    Ok(())
}
